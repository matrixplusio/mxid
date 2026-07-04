import { useCallback, useEffect, useRef, useState, type ChangeEvent, type ReactNode } from 'react'
import { Camera, Loader2 } from 'lucide-react'
import { Button, Modal } from './index'
import { toast } from './toast'

export interface AvatarUploadTexts {
  /** Crop dialog title. */
  cropTitle: string
  /** Zoom slider label. */
  zoom: string
  confirm: string
  cancel: string
  /** Shown (toast) when the chosen file exceeds maxMB. */
  tooLarge: string
  /** Hover/title hint on the avatar circle. */
  hint?: string
}

// Fixed square output edge (px). A circular avatar only needs a square source;
// the circle is a CSS mask. 512 is crisp on retina while keeping the base64
// small (well under the backend cap) regardless of the original file size.
const OUTPUT = 512
// Crop viewport edge (px) in the dialog.
const VIEW = 280

/* ───────────────────────── AvatarCropper ─────────────────────────
   Interactive circular crop: drag to reposition, slider to zoom. Exports a
   square PNG data URL of the visible circle's bounding box. No dependencies —
   plain canvas + pointer events. */
function AvatarCropper({
  src,
  texts,
  onConfirm,
  onCancel,
}: {
  src: string
  texts: AvatarUploadTexts
  onConfirm: (dataURL: string) => void
  onCancel: () => void
}) {
  const imgRef = useRef<HTMLImageElement | null>(null)
  const [nat, setNat] = useState<{ w: number; h: number } | null>(null)
  const [zoom, setZoom] = useState(1)
  const [offset, setOffset] = useState({ x: 0, y: 0 })
  const [busy, setBusy] = useState(false)
  const drag = useRef<{ x: number; y: number } | null>(null)

  // baseScale makes the shorter image edge exactly fill the viewport (cover).
  const baseScale = nat ? VIEW / Math.min(nat.w, nat.h) : 1
  const scale = baseScale * zoom
  const dispW = nat ? nat.w * scale : 0
  const dispH = nat ? nat.h * scale : 0

  const clamp = useCallback(
    (o: { x: number; y: number }) => {
      // Keep the viewport fully covered: image edges never cross into the frame.
      const minX = VIEW - dispW
      const minY = VIEW - dispH
      return {
        x: Math.min(0, Math.max(minX, o.x)),
        y: Math.min(0, Math.max(minY, o.y)),
      }
    },
    [dispW, dispH],
  )

  // Load natural dims + center the image when a new src arrives.
  useEffect(() => {
    const img = new Image()
    img.onload = () => {
      imgRef.current = img
      setNat({ w: img.naturalWidth, h: img.naturalHeight })
      const bs = VIEW / Math.min(img.naturalWidth, img.naturalHeight)
      setZoom(1)
      setOffset({
        x: (VIEW - img.naturalWidth * bs) / 2,
        y: (VIEW - img.naturalHeight * bs) / 2,
      })
    }
    img.src = src
  }, [src])

  const onPointerDown = (e: React.PointerEvent) => {
    ;(e.target as HTMLElement).setPointerCapture(e.pointerId)
    drag.current = { x: e.clientX, y: e.clientY }
  }
  const onPointerMove = (e: React.PointerEvent) => {
    if (!drag.current) return
    const dx = e.clientX - drag.current.x
    const dy = e.clientY - drag.current.y
    drag.current = { x: e.clientX, y: e.clientY }
    setOffset((o) => clamp({ x: o.x + dx, y: o.y + dy }))
  }
  const onPointerUp = () => {
    drag.current = null
  }

  const onZoom = (z: number) => {
    // Zoom around the viewport centre so the framed subject stays put.
    const oldS = scale
    const newS = baseScale * z
    setOffset((o) =>
      clamp({
        x: VIEW / 2 - ((VIEW / 2 - o.x) / oldS) * newS,
        y: VIEW / 2 - ((VIEW / 2 - o.y) / oldS) * newS,
      }),
    )
    setZoom(z)
  }

  const confirm = () => {
    const img = imgRef.current
    if (!img || !nat) return
    setBusy(true)
    try {
      const canvas = document.createElement('canvas')
      canvas.width = OUTPUT
      canvas.height = OUTPUT
      const ctx = canvas.getContext('2d')
      if (!ctx) {
        onCancel()
        return
      }
      // Source rect (in original-image px) that the viewport currently frames.
      const sW = VIEW / scale
      const sH = VIEW / scale
      const sx = -offset.x / scale
      const sy = -offset.y / scale
      ctx.drawImage(img, sx, sy, sW, sH, 0, 0, OUTPUT, OUTPUT)
      onConfirm(canvas.toDataURL('image/png'))
    } finally {
      setBusy(false)
    }
  }

  return (
    <Modal open title={texts.cropTitle} onClose={onCancel} size="sm">
      <div className="flex flex-col items-center gap-5">
        <div
          className="relative touch-none overflow-hidden rounded-full bg-surface-muted ring-1 ring-border"
          style={{ width: VIEW, height: VIEW }}
          onPointerDown={onPointerDown}
          onPointerMove={onPointerMove}
          onPointerUp={onPointerUp}
          onPointerLeave={onPointerUp}
        >
          {nat && (
            <img
              src={src}
              alt=""
              draggable={false}
              className="max-w-none cursor-grab select-none active:cursor-grabbing"
              style={{
                width: nat.w,
                height: nat.h,
                transform: `translate(${offset.x}px, ${offset.y}px) scale(${scale})`,
                transformOrigin: '0 0',
              }}
            />
          )}
          <div className="pointer-events-none absolute inset-0 rounded-full ring-2 ring-white/70" />
        </div>

        <div className="flex w-full items-center gap-3">
          <span className="text-xs text-muted">{texts.zoom}</span>
          <input
            type="range"
            min={1}
            max={3}
            step={0.01}
            value={zoom}
            onChange={(e) => onZoom(Number(e.target.value))}
            className="h-1 flex-1 cursor-pointer accent-primary"
          />
        </div>

        <div className="flex w-full gap-3">
          <Button type="button" variant="secondary" className="flex-1" onClick={onCancel} disabled={busy}>
            {texts.cancel}
          </Button>
          <Button type="button" className="flex-1" onClick={confirm} loading={busy}>
            {texts.confirm}
          </Button>
        </div>
      </div>
    </Modal>
  )
}

/* ───────────────────────── AvatarUpload ─────────────────────────
   A clickable circular avatar. Click → pick image → crop → onChange(dataURL).
   fallback renders when there is no image (initial letter / icon per caller). */
export function AvatarUpload({
  value,
  onChange,
  texts,
  fallback,
  size = 80,
  maxMB = 3,
  disabled = false,
}: {
  value?: string | null
  onChange: (dataURL: string) => void
  texts: AvatarUploadTexts
  fallback?: ReactNode
  size?: number
  maxMB?: number
  disabled?: boolean
}) {
  const fileRef = useRef<HTMLInputElement>(null)
  const [pending, setPending] = useState<string | null>(null)

  const pick = (e: ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0]
    e.target.value = '' // allow re-selecting the same file
    if (!file) return
    if (file.size > maxMB * 1024 * 1024) {
      toast.error(texts.tooLarge)
      return
    }
    const r = new FileReader()
    r.onload = () => setPending(r.result as string)
    r.onerror = () => toast.error(texts.tooLarge)
    r.readAsDataURL(file)
  }

  return (
    <>
      <div
        role="button"
        tabIndex={disabled ? -1 : 0}
        onClick={() => !disabled && fileRef.current?.click()}
        onKeyDown={(e) => (e.key === 'Enter' || e.key === ' ') && !disabled && fileRef.current?.click()}
        title={texts.hint}
        style={{ width: size, height: size }}
        className="group relative flex shrink-0 cursor-pointer items-center justify-center overflow-hidden rounded-full bg-primary/15 text-primary ring-1 ring-border"
      >
        {value ? (
          <img src={value} alt="" className="h-full w-full object-cover" />
        ) : (
          fallback
        )}
        <div className="absolute inset-0 hidden items-center justify-center bg-black/50 text-white group-hover:flex">
          <Camera className="h-5 w-5" />
        </div>
        <input ref={fileRef} type="file" accept="image/png,image/jpeg,image/webp" onChange={pick} className="hidden" />
      </div>

      {pending && (
        <AvatarCropper
          src={pending}
          texts={texts}
          onCancel={() => setPending(null)}
          onConfirm={(dataURL) => {
            setPending(null)
            onChange(dataURL)
          }}
        />
      )}
    </>
  )
}

// Re-export the spinner so callers can show upload progress if they wish.
export { Loader2 as AvatarSpinner }

/** Build the crop-dialog text set from an i18n `t`. Centralises the keys so the
 *  three avatar call sites (portal profile, console account, console user detail)
 *  stay consistent. */
export function avatarTexts(t: (k: string) => string): AvatarUploadTexts {
  return {
    cropTitle: t('common.cropTitle'),
    zoom: t('common.zoom'),
    confirm: t('common.confirm'),
    cancel: t('common.cancel'),
    tooLarge: t('account.fields.sizeHint'),
    hint: t('account.fields.avatar'),
  }
}
