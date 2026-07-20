import { StrictMode } from 'react'
import { createRoot } from 'react-dom/client'
import { BrowserRouter } from 'react-router-dom'
import './index.css'
import App from './App'
import { upgradeToHTTPS } from '@mxid/shared'

// Force HTTPS before the app loads — an http:// origin fails the CSRF
// allow-list on every write. See upgradeToHTTPS for the localhost/IP carve-outs.
upgradeToHTTPS()

createRoot(document.getElementById('root')!).render(
  <StrictMode>
    <BrowserRouter basename={import.meta.env.BASE_URL.replace(/\/$/, '')}>
      <App />
    </BrowserRouter>
  </StrictMode>,
)
