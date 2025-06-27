import { jwtDecode } from 'jwt-decode'
import { baseUrl } from './utils'
import config from './config'
import { removeHomeCache } from './utils/removeHomeCache'

// config sent from server may contain authentication info, for example when the user is authenticated
// by a reverse proxy request header
if (config.auth) {
  try {
    storeAuthenticationInfo(config.auth)
  } catch (e) {
    // eslint-disable-next-line no-console
    console.log(e)
  }
}

function storeAuthenticationInfo(authInfo) {
  authInfo.token && localStorage.setItem('token', authInfo.token)
  localStorage.setItem('userId', authInfo.id)
  localStorage.setItem('name', authInfo.name)
  localStorage.setItem('username', authInfo.username)
  authInfo.avatar && localStorage.setItem('avatar', authInfo.avatar)
  localStorage.setItem('role', authInfo.isAdmin ? 'admin' : 'regular')
  localStorage.setItem('subsonic-salt', authInfo.subsonicSalt)
  localStorage.setItem('subsonic-token', authInfo.subsonicToken)
  localStorage.setItem('is-authenticated', 'true')
}

const authProvider = {
  login: ({ username, password }) => {
    let url = baseUrl('/auth/login')
    if (config.firstTime) {
      url = baseUrl('/auth/createAdmin')
    }
    const request = new Request(url, {
      method: 'POST',
      body: JSON.stringify({ username, password }),
      headers: new Headers({ 'Content-Type': 'application/json' }),
    })
    return fetch(request)
      .then((response) => {
        if (response.status < 200 || response.status >= 300) {
          throw new Error(response.statusText)
        }
        return response.json()
      })
      .then((response) => {
        jwtDecode(response.token) // Validate token
        storeAuthenticationInfo(response)
        // Avoid "going to create admin" dialog after logout/login without a refresh
        config.firstTime = false
        removeHomeCache()
        return response
      })
      .catch((error) => {
        if (
          error.message === 'Failed to fetch' ||
          error.stack === 'TypeError: Failed to fetch'
        ) {
          throw new Error('errors.network_error')
        }

        throw new Error(error)
      })
  },

  logout: () => {
    removeItems()
    return Promise.resolve()
  },

  checkAuth: () =>
    localStorage.getItem('is-authenticated')
      ? Promise.resolve()
      : Promise.reject(),

  checkError: ({ status }) => {
    if (status === 401) {
      removeItems()
      return Promise.reject()
    }
    return Promise.resolve()
  },

  getPermissions: () => {
    const role = localStorage.getItem('role')
    return role ? Promise.resolve(role) : Promise.reject()
  },

  getIdentity: () => {
    return Promise.resolve({
      id: localStorage.getItem('username'),
      fullName: localStorage.getItem('name'),
      avatar: localStorage.getItem('avatar'),
    })
  },
}

const removeItems = () => {
  localStorage.removeItem('token')
  localStorage.removeItem('userId')
  localStorage.removeItem('name')
  localStorage.removeItem('username')
  localStorage.removeItem('avatar')
  localStorage.removeItem('role')
  localStorage.removeItem('subsonic-salt')
  localStorage.removeItem('subsonic-token')
  localStorage.removeItem('is-authenticated')

  // Clean up OIDC auth token cookie on logout
  document.cookie =
    'oidc_auth_token=; Path=/; Expires=Thu, 01 Jan 1970 00:00:01 GMT;'
}

// Check for OIDC authentication after redirect
function checkOIDCAuthentication() {
  const urlParams = new URLSearchParams(window.location.search)
  if (urlParams.get('oidc_login') === 'success') {
    // Get authentication data from cookies
    const token = getCookie('oidc_auth_token')
    const payloadCookie = getCookie('oidc_auth_payload')

    if (token && payloadCookie) {
      try {
        // Decode base64 encoded payload
        const payloadJson = atob(payloadCookie)
        const payload = JSON.parse(payloadJson)
        payload.token = token
        jwtDecode(token) // Validate token
        storeAuthenticationInfo(payload)

        // Clean up payload cookie (but keep auth token for browser requests)
        document.cookie =
          'oidc_auth_payload=; Path=/; Expires=Thu, 01 Jan 1970 00:00:01 GMT;'

        // Clean up URL
        window.history.replaceState(
          {},
          document.title,
          window.location.pathname + window.location.hash,
        )

        // Avoid "going to create admin" dialog after logout/login without a refresh
        config.firstTime = false
        removeHomeCache()

        return true
      } catch (e) {
        // eslint-disable-next-line no-console
        console.error('Error processing OIDC authentication:', e)
      }
    }
  }
  return false
}

function getCookie(name) {
  const value = `; ${document.cookie}`
  const parts = value.split(`; ${name}=`)
  if (parts.length === 2) return parts.pop().split(';').shift()
  return null
}

// Check for OIDC authentication on load
checkOIDCAuthentication()

export default authProvider
