import { StrictMode } from 'react'
import { createRoot } from 'react-dom/client'
import { BrowserRouter } from 'react-router-dom'
import './index.css'
import App from './App'
import { upgradeToHTTPS } from '@mxid/shared'

// Force HTTPS in production. Reaching the portal over http:// makes the browser
// send `Origin: http://…`, which never matches the https allow-list → every
// state-changing POST (login included) is rejected by the CSRF guard with a
// bewildering 403. Redirect before the app (and its cookies) load. No-op on
// localhost and non-prod builds so dev over http keeps working.
upgradeToHTTPS()

createRoot(document.getElementById('root')!).render(
  <StrictMode>
    <BrowserRouter basename={import.meta.env.BASE_URL.replace(/\/$/, '')}>
      <App />
    </BrowserRouter>
  </StrictMode>,
)
