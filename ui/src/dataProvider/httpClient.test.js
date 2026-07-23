import { fetchUtils } from 'react-admin'
import { jwtDecode } from 'jwt-decode'
import config from '../config'
import httpClient from './httpClient'

vi.mock('react-admin', () => ({
  fetchUtils: {
    fetchJson: vi.fn(),
  },
}))

vi.mock('jwt-decode', () => ({
  jwtDecode: vi.fn(() => ({ uid: 'user-1' })),
}))

vi.mock('../utils/removeHomeCache', () => ({
  removeHomeCache: vi.fn(),
}))

describe('httpClient OIDC refresh', () => {
  const originalOIDCEnabled = config.oidcEnabled

  beforeEach(() => {
    config.oidcEnabled = true
    localStorage.clear()
    localStorage.setItem('token', 'expired-token')
    localStorage.setItem('oidc-authenticated', 'true')
    fetchUtils.fetchJson.mockReset()
    jwtDecode.mockClear()
    vi.stubGlobal('fetch', vi.fn())
  })

  afterEach(() => {
    config.oidcEnabled = originalOIDCEnabled
    vi.unstubAllGlobals()
  })

  it('stores the refreshed token and retries with the new authorization header', async () => {
    const unauthorized = { status: 401 }
    const successfulResponse = {
      headers: new Headers(),
      json: { id: 'song-1' },
    }
    fetchUtils.fetchJson
      .mockRejectedValueOnce(unauthorized)
      .mockResolvedValueOnce(successfulResponse)
    fetch.mockResolvedValue({
      ok: true,
      json: () => Promise.resolve({ token: 'refreshed-token' }),
    })

    const response = await httpClient('/api/song/1')

    expect(response).toBe(successfulResponse)
    expect(fetch).toHaveBeenCalledWith(
      '/auth/oidc/refresh',
      expect.objectContaining({
        method: 'POST',
        credentials: 'include',
      }),
    )
    expect(fetchUtils.fetchJson).toHaveBeenCalledTimes(2)
    const retryOptions = fetchUtils.fetchJson.mock.calls[1][1]
    expect(retryOptions.headers.get('X-ND-Authorization')).toBe(
      'Bearer refreshed-token',
    )
    expect(localStorage.getItem('token')).toBe('refreshed-token')
    expect(localStorage.getItem('userId')).toBe('user-1')
  })

  it('does not attempt OIDC refresh for a password session', async () => {
    localStorage.clear()
    const unauthorized = { status: 401 }
    fetchUtils.fetchJson.mockRejectedValue(unauthorized)

    await expect(httpClient('/api/song/1')).rejects.toBe(unauthorized)

    expect(fetch).not.toHaveBeenCalled()
    expect(fetchUtils.fetchJson).toHaveBeenCalledTimes(1)
  })
})
