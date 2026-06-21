// Built-in brand icons for common IAM-integrated apps.
//
// Sourced from `simple-icons` npm package — authoritative SVG paths +
// official brand hex. We re-export only a curated subset (~40 brands) so
// the IconPicker UI stays browsable and bundle size stays small (~30KB
// for the slice we use).
//
// Stored format in DB: `builtin:<slug>` (e.g. "builtin:grafana"). The slug
// is simple-icons' own slug; if simple-icons removes/renames a brand the
// admin will see a fallback letter and can switch to upload mode.
//
// Brands NOT in simple-icons (trademark removals: Slack, AWS, Azure, Lark,
// Feishu, DingTalk) fall back to the upload mode. A handful of high-value
// targets (JumpServer) have hand-crafted SVGs in CUSTOM_ICONS below so the
// icon picker still surfaces them.

import { parseAppIcon } from './app-icon'
import * as si from 'simple-icons'

export interface BuiltinIcon {
  slug: string
  name: string
  // Single SVG path. simple-icons normalizes everything to a 24x24 viewbox.
  path: string
  color: string
  category: 'iam' | 'devops' | 'collab' | 'storage' | 'cloud' | 'observability' | 'misc'
}

// Generic placeholder for `builtin:<unknown>` strings (e.g. icon removed
// from a future simple-icons release). Keeps the UI from crashing.
export const FALLBACK_ICON: BuiltinIcon = {
  slug: 'fallback',
  name: 'App',
  path: 'M3 3h18v18H3V3zm2 2v14h14V5H5zm3 3h8v2H8V8zm0 4h8v2H8v-2zm0 4h5v2H8v-2z',
  color: '#64748b',
  category: 'misc',
}

// pick wraps simple-icons access with a category tag. Throws at startup if
// simple-icons doesn't ship the requested slug — better to crash here than
// silently swallow into the UI.
function pick(slug: string, category: BuiltinIcon['category'], nameOverride?: string): BuiltinIcon {
  const key = 'si' + slug.charAt(0).toUpperCase() + slug.slice(1)
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const ic = (si as any)[key] as { title: string; path: string; hex: string; slug: string } | undefined
  if (!ic) {
    // Don't throw — leave a visibly-broken placeholder so we notice in dev.
    return { ...FALLBACK_ICON, slug, name: slug }
  }
  return {
    slug: ic.slug,
    name: nameOverride ?? ic.title,
    path: ic.path,
    color: '#' + ic.hex,
    category,
  }
}

// Hand-crafted icons for brands simple-icons doesn't ship. Keep entries
// minimal — single path, 24x24 viewbox, brand-official hex. Adding more is
// a deliberate maintenance burden (no upstream updates, no normalisation),
// so reserve this for brands actively integrated by users.
const CUSTOM_ICONS: BuiltinIcon[] = [
  {
    slug: 'jumpserver',
    name: 'JumpServer',
    // Official JumpServer hexagon "S" mark, normalised from fit2cloud's
    // brand SVG to a 24x24 viewbox. The four source paths share one fill so
    // they collapse cleanly into a single path string.
    path: 'M 11.33,3.32 C 10.67,3.74 9.94,4.1 9.22,4.47 C 8.43,4.89 7.64,5.37 6.73,5.86 C 8.61,7.07 10.43,8.22 12.36,9.43 C 12.0,9.67 11.7,9.79 11.46,9.97 C 11.15,10.15 10.97,10.15 10.67,9.97 C 9.16,9.06 7.58,8.16 6.07,7.19 C 5.4,6.77 4.92,6.7 4.31,7.13 C 3.71,7.55 3.65,8.1 4.31,8.46 C 4.62,8.64 4.92,8.82 5.22,9.06 C 6.92,10.09 8.61,11.12 10.18,12.21 C 11.21,12.88 12.12,12.88 13.09,12.27 C 14.0,11.73 14.9,11.18 15.81,10.64 C 16.18,10.46 16.48,10.21 16.9,9.97 C 15.09,8.82 13.39,7.73 11.64,6.58 C 11.94,6.34 12.18,6.22 12.42,6.04 C 12.73,5.8 12.97,5.8 13.33,5.98 C 14.84,6.83 16.36,7.67 17.87,8.52 C 18.9,9.06 18.9,9.06 19.69,8.22 C 19.99,7.85 19.93,7.43 19.5,7.19 C 17.08,5.86 14.66,4.53 12.3,3.19 C 11.88,3.13 11.64,3.13 11.33,3.32 M 12.97,13.97 C 12.12,14.39 11.27,14.45 10.43,13.91 C 8.43,12.7 6.49,11.55 4.5,10.34 C 4.31,10.21 4.13,10.09 3.83,9.97 C 3.83,10.76 3.83,11.43 3.83,12.09 C 3.83,12.51 3.95,12.7 4.25,12.88 C 6.37,14.09 8.49,15.36 10.61,16.57 C 11.33,16.99 12.12,16.99 12.79,16.63 C 14.18,15.9 18.11,13.48 19.44,12.7 C 19.56,12.64 19.75,12.45 19.75,12.33 C 19.75,11.55 19.75,10.76 19.75,9.91 C 19.5,10.03 19.32,10.15 19.14,10.28 C 17.99,11.0 14.18,13.36 12.97,13.97 M 14.36,16.75 C 13.76,17.05 13.15,17.42 12.54,17.66 C 11.88,17.96 11.15,17.96 10.49,17.54 C 9.94,17.17 9.34,16.87 8.79,16.57 C 7.82,15.96 6.8,15.36 5.83,14.75 C 5.16,14.33 4.5,13.97 3.71,13.54 C 3.71,14.39 3.71,15.12 3.71,15.9 C 3.71,16.02 3.83,16.21 3.95,16.27 C 6.13,17.6 8.31,18.87 10.55,20.14 C 11.27,20.56 12.12,20.56 12.85,20.14 C 14.18,19.41 18.29,16.93 19.56,16.21 C 19.69,16.15 19.81,16.02 19.81,15.9 C 19.81,15.12 19.81,14.33 19.81,13.54 C 19.75,13.54 19.63,13.54 19.56,13.6 C 18.84,14.09 15.21,16.27 14.36,16.75 M 12.06,1.5 L 12.06,1.5 L 2.74,6.83 L 2.68,6.83 L 2.68,16.81 L 12.0,22.5 L 21.26,16.81 L 21.32,16.75 L 21.32,6.83 L 12.06,1.5 M 21.08,16.75 L 11.94,22.32 L 2.8,16.75 L 2.8,7.01 L 11.94,1.74 L 21.08,7.01 L 21.08,16.75',
    color: '#2B937C',
    category: 'iam',
  },
  {
    // 企业微信 (WeCom) — simple-icons dropped it on trademark grounds, so the
    // mark is normalised here from tdesign's brand glyph to a 24x24 viewbox.
    slug: 'wecom',
    name: 'WeCom',
    path: 'M 16.88,8.44 L 16.88,8.43 A 6.05,6.05 0.0 0,0 15.8,6.9 C 14.64,5.7 12.99,4.89 11.12,4.68 A 8.53,8.53 0.0 0,0 9.18,4.68 L 9.18,4.68 C 7.29,4.89 5.62,5.7 4.46,6.89 A 6.14,6.14 0.0 0,0 3.37,8.43 A 5.23,5.23 0.0 0,0 2.83,10.73 C 2.83,11.74 3.14,12.76 3.74,13.66 L 3.74,13.67 C 4.1,14.22 4.75,14.95 5.25,15.35 L 6.15,16.08 L 5.96,16.88 L 6.44,16.63 L 7.09,16.31 L 7.79,16.51 C 8.21,16.64 8.66,16.72 9.18,16.78 L 9.18,16.78 Q 9.65,16.83 10.12,16.83 C 10.45,16.83 10.78,16.81 11.12,16.78 A 8.25,8.25 0.0 0,0 12.36,16.54 C 12.45,17.18 12.75,17.77 13.21,18.2 C 12.61,18.39 11.97,18.53 11.32,18.6 C 10.92,18.64 10.51,18.66 10.12,18.66 Q 9.55,18.66 8.97,18.6 A 9.81,9.81 0.0 0,1 7.27,18.27 L 4.66,19.59 C 4.66,19.59 4.4,19.71 4.26,19.71 C 3.88,19.71 3.62,19.45 3.62,19.06 C 3.62,18.83 3.68,18.51 3.73,18.29 L 4.09,16.78 C 3.43,16.24 2.66,15.36 2.21,14.68 A 7.11,7.11 0.0 0,1 1.0,10.73 A 7.06,7.06 0.0 0,1 1.72,7.62 A 7.98,7.98 0.0 0,1 3.14,5.61 C 4.62,4.09 6.7,3.11 8.97,2.86 A 10.36,10.36 0.0 0,1 11.32,2.86 C 13.59,3.11 15.64,4.1 17.12,5.62 A 7.88,7.88 0.0 0,1 18.53,7.63 C 18.96,8.5 19.24,9.41 19.24,10.36 A 2.81,2.81 0.0 0,0 17.4,10.36 C 17.4,9.77 17.23,9.14 16.89,8.44 L 16.88,8.44 M 20.66,14.83 L 20.64,14.81 L 20.62,14.79 L 20.6,14.78 L 20.51,14.69 A 3.89,3.89 0.0 0,1 19.44,12.68 Q 19.44,12.65 19.43,12.61 L 19.43,12.56 L 19.4,12.43 A 1.19,1.19 0.0 0,0 19.07,11.87 A 1.27,1.27 0.0 0,0 17.27,11.87 A 1.28,1.28 0.0 0,0 17.27,13.67 C 17.45,13.84 17.66,13.95 17.89,14.01 C 17.91,14.02 17.94,14.02 17.96,14.02 Q 17.98,14.02 18.0,14.03 Q 18.02,14.03 18.04,14.03 A 3.89,3.89 0.0 0,1 20.08,15.12 C 20.13,15.16 20.17,15.21 20.2,15.25 A 0.3,0.3 0.0 0,0 20.63,15.25 A 0.32,0.32 0.0 0,0 20.66,14.83 M 19.7,18.84 L 19.68,18.86 C 19.57,18.95 19.39,18.95 19.26,18.83 A 0.3,0.3 0.0 0,1 19.26,18.4 C 19.31,18.37 19.35,18.32 19.39,18.28 L 19.39,18.28 A 3.91,3.91 0.0 0,0 20.48,16.19 Q 20.49,16.17 20.49,16.15 C 20.49,16.13 20.49,16.1 20.5,16.07 A 1.27,1.27 0.0 0,1 22.63,15.46 A 1.28,1.28 0.0 0,1 22.63,17.26 C 22.48,17.42 22.28,17.53 22.07,17.59 L 21.94,17.62 L 21.89,17.63 Q 21.86,17.63 21.82,17.63 A 3.85,3.85 0.0 0,0 19.82,18.71 L 19.73,18.8 Q 19.73,18.81 19.72,18.82 Q 19.71,18.83 19.7,18.84 M 15.67,17.87 L 15.7,17.9 L 15.72,17.91 Q 15.73,17.92 15.74,17.93 L 15.83,18.02 A 3.9,3.9 0.0 0,1 16.9,20.03 Q 16.9,20.06 16.91,20.09 Q 16.91,20.12 16.91,20.15 L 16.94,20.28 C 17.0,20.49 17.11,20.68 17.27,20.84 C 17.76,21.33 18.57,21.33 19.07,20.84 A 1.28,1.28 0.0 0,0 19.07,19.04 A 1.28,1.28 0.0 0,0 18.45,18.7 C 18.43,18.69 18.4,18.69 18.38,18.69 Q 18.36,18.69 18.34,18.68 L 18.3,18.68 A 3.9,3.9 0.0 0,1 16.25,17.59 A 1.28,1.28 0.0 0,1 16.13,17.46 A 0.3,0.3 0.0 0,0 15.71,17.46 A 0.3,0.3 0.0 0,0 15.67,17.87 M 16.63,13.88 L 16.65,13.86 A 0.29,0.29 0.0 0,1 17.06,13.89 A 0.3,0.3 0.0 0,1 17.06,14.32 C 17.02,14.35 16.98,14.39 16.93,14.44 L 16.93,14.44 A 3.91,3.91 0.0 0,0 15.85,16.53 L 15.84,16.57 C 15.84,16.59 15.84,16.62 15.83,16.65 A 1.27,1.27 0.0 0,1 13.7,17.26 A 1.28,1.28 0.0 0,1 13.7,15.46 C 13.85,15.29 14.05,15.18 14.25,15.13 L 14.38,15.1 Q 14.41,15.1 14.44,15.09 Q 14.47,15.09 14.5,15.09 A 3.85,3.85 0.0 0,0 16.51,14.01 L 16.59,13.92 L 16.61,13.9 L 16.63,13.88',
    color: '#2D8CFF',
    category: 'collab',
  },
  {
    // 钉钉 (DingTalk) — normalised from Ant Design's brand glyph (1024 viewbox)
    // down to 24x24. simple-icons dropped it on trademark grounds.
    slug: 'dingtalk',
    name: 'DingTalk',
    path: 'M 13.63,5.14 C 9.63,3.68 3.79,1.02 3.79,1.02 C 3.37,0.91 3.31,1.31 3.31,1.31 C 3.18,2.93 4.2,5.56 4.73,6.15 C 5.26,6.74 13.17,9.15 13.17,9.15 C 13.17,9.15 7.08,7.93 5.61,7.5 C 4.14,7.08 4.61,7.97 4.61,7.97 C 4.91,9.6 6.33,11.46 7.45,11.63 C 8.56,11.81 13.27,11.74 13.27,11.74 C 13.27,11.74 12.33,11.85 10.8,12.05 C 9.67,12.21 8.24,12.38 7.87,12.52 C 6.99,12.85 8.5,14.18 8.5,14.18 C 10.74,16.21 11.93,15.51 11.93,15.51 C 12.81,15.23 13.55,15.03 14.18,14.87 L 13.4,18.11 L 15.64,18.11 L 14.41,23.0 L 19.84,15.81 L 16.99,15.81 L 17.58,14.79 C 17.59,14.8 17.59,14.81 17.59,14.81 C 17.59,14.81 19.61,11.58 20.38,9.93 L 20.4,9.91 L 20.4,9.91 C 20.53,9.62 20.62,9.38 20.66,9.22 C 21.11,7.34 17.63,6.6 13.63,5.14',
    color: '#1677FF',
    category: 'collab',
  },
  {
    // 飞书 (Feishu / Lark) — normalised from icon-park's brand glyph (48 viewbox)
    // to 24x24. simple-icons has no entry for it.
    slug: 'feishu',
    name: 'Feishu',
    path: 'M 22.42,1.08 L 1.0,7.05 L 6.15,12.32 L 10.92,12.41 L 16.41,7.05 C 16.26,6.76 16.19,6.51 16.19,6.31 C 16.19,5.86 16.37,5.5 16.64,5.25 C 17.11,4.81 17.68,4.75 18.34,5.05 L 22.42,1.08 M 23.0,1.5 L 17.03,22.92 L 11.76,17.77 L 11.68,13.0 L 16.99,7.6 C 17.28,7.81 17.6,7.9 17.94,7.88 C 18.45,7.85 18.78,7.54 18.94,7.36 C 19.09,7.18 19.27,6.88 19.26,6.42 C 19.25,6.12 19.15,5.85 18.96,5.59 L 23.0,1.5',
    color: '#3370FF',
    category: 'collab',
  },
]

export const BUILTIN_ICONS: BuiltinIcon[] = [
  // ─── IAM / SSO ───
  pick('okta', 'iam'),
  pick('keycloak', 'iam'),
  pick('auth0', 'iam'),
  ...CUSTOM_ICONS.filter((i) => i.category === 'iam'),

  // ─── Atlassian ───
  pick('jira', 'collab'),
  pick('confluence', 'collab'),

  // ─── DevOps ───
  pick('grafana', 'observability'),
  pick('gitlab', 'devops'),
  pick('github', 'devops'),
  pick('gitea', 'devops'),
  pick('jenkins', 'devops'),
  pick('harbor', 'devops'),
  pick('argo', 'devops'),
  pick('spinnaker', 'devops'),
  pick('rancher', 'devops'),
  pick('helm', 'devops'),
  pick('traefikproxy', 'devops', 'Traefik'),
  pick('consul', 'devops'),
  pick('vault', 'devops', 'HashiCorp Vault'),
  pick('vmware', 'devops'),
  pick('kubernetes', 'devops'),
  pick('docker', 'devops'),
  pick('nginx', 'devops'),

  // ─── Collab / Communication ───
  ...CUSTOM_ICONS.filter((i) => i.category === 'collab'),
  pick('discord', 'collab'),
  pick('telegram', 'collab'),
  pick('zoom', 'collab'),
  pick('wechat', 'collab'),
  pick('notion', 'collab'),
  pick('figma', 'collab'),
  pick('linear', 'collab'),
  pick('clickup', 'collab'),
  pick('obsidian', 'collab'),

  // ─── Storage / Data ───
  pick('nextcloud', 'storage'),
  pick('minio', 'storage'),
  pick('postgresql', 'storage'),
  pick('mysql', 'storage'),
  pick('redis', 'storage'),
  pick('mongodb', 'storage'),
  pick('etcd', 'storage'),
  pick('apachecassandra', 'storage', 'Cassandra'),
  pick('clickhouse', 'storage'),

  // ─── Cloud ───
  pick('googlecloud', 'cloud'),
  pick('alibabacloud', 'cloud'),

  // ─── Observability ───
  pick('prometheus', 'observability'),
  pick('elasticsearch', 'observability'),
  pick('kibana', 'observability'),
  pick('sentry', 'observability'),
  pick('datadog', 'observability'),
  pick('newrelic', 'observability'),
  pick('splunk', 'observability'),
  pick('pagerduty', 'observability'),

  // ─── Misc ───
  pick('apachekafka', 'misc', 'Kafka'),
  pick('rabbitmq', 'misc'),
  pick('apacheairflow', 'misc', 'Airflow'),
  pick('natsdotio', 'misc', 'NATS'),
]

// Map for O(1) lookup by slug.
const BY_SLUG = new Map(BUILTIN_ICONS.map((i) => [i.slug, i]))

export function getBuiltinIcon(slug: string): BuiltinIcon | undefined {
  return BY_SLUG.get(slug)
}

// resolveIcon resolves an app.icon column value to a BuiltinIcon when the
// value is `builtin:<slug>`; otherwise returns undefined (caller renders
// URL via <img> or falls back to a placeholder).
export function resolveIcon(value: string | null | undefined): BuiltinIcon | undefined {
  const p = parseAppIcon(value)
  if (p.kind === 'builtin' && p.slug) return getBuiltinIcon(p.slug)
  return undefined
}
