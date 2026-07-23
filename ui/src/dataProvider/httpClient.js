import { fetchUtils } from 'react-admin'
import { v4 as uuidv4 } from 'uuid'
import { baseUrl } from '../utils'
import config from '../config'
import { jwtDecode } from 'jwt-decode'
import { removeHomeCache } from '../utils/removeHomeCache'

const customAuthorizationHeader = 'X-ND-Authorization'
export const clientUniqueIdHeader = 'X-ND-Client-Unique-Id'
export const clientUniqueId = uuidv4()
const oidcAuthenticatedKey = 'oidc-authenticated'
let oidcRefreshPromise

const storeToken = (token) => {
  const decoded = jwtDecode(token)
  localStorage.setItem('token', token)
  localStorage.setItem('userId', decoded.uid)
  // Avoid going to create admin dialog after logout/login without a refresh
  config.firstTime = false
  removeHomeCache()
}

const clearAuthentication = () => {
  const authKeys = [
    'token',
    'userId',
    'name',
    'username',
    'avatar',
    'role',
    'subsonic-salt',
    'subsonic-token',
    'is-authenticated',
    oidcAuthenticatedKey,
  ]
  authKeys.forEach((key) => localStorage.removeItem(key))
  document.cookie =
    'oidc_auth_token=; Path=/; Expires=Thu, 01 Jan 1970 00:00:01 GMT;'
}

const refreshOIDCSession = () => {
  if (!oidcRefreshPromise) {
    oidcRefreshPromise = fetch(baseUrl('/auth/oidc/refresh'), {
      method: 'POST',
      credentials: 'include',
      headers: new Headers({ Accept: 'application/json' }),
    })
      .then(async (response) => {
        if (!response.ok) {
          throw new Error('OIDC session refresh failed')
        }
        const payload = await response.json()
        if (!payload.token) {
          throw new Error('OIDC session refresh returned no token')
        }
        storeToken(payload.token)
        return payload.token
      })
      .finally(() => {
        oidcRefreshPromise = undefined
      })
  }
  return oidcRefreshPromise
}

const httpClient = async (url, options = {}) => {
  url = baseUrl(url)
  if (!options.headers) {
    options.headers = new Headers({ Accept: 'application/json' })
  }
  options.headers.set(clientUniqueIdHeader, clientUniqueId)
  const token = localStorage.getItem('token')
  if (token) {
    options.headers.set(customAuthorizationHeader, `Bearer ${token}`)
  }

  let response
  try {
    response = await fetchUtils.fetchJson(url, options)
  } catch (error) {
    const canRefreshOIDC =
      error?.status === 401 &&
      config.oidcEnabled &&
      localStorage.getItem(oidcAuthenticatedKey) === 'true'
    if (canRefreshOIDC) {
      let refreshedToken
      try {
        refreshedToken = await refreshOIDCSession()
      } catch {
        clearAuthentication()
        window.location.href = baseUrl('/login')
        throw error
      }
      options.headers.set(customAuthorizationHeader, `Bearer ${refreshedToken}`)
      response = await fetchUtils.fetchJson(url, options)
    } else {
      throw error
    }
  }

  const newToken = response.headers.get(customAuthorizationHeader)
  if (newToken) {
    storeToken(newToken)
  }
  return response
}

export default httpClient
