import { act, renderHook } from '@testing-library/react-hooks'
import { waitFor } from '@testing-library/react'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import { httpClient } from '../dataProvider'
import { useEndlessPreference } from './useEndlessPreference'

vi.mock('../dataProvider', () => ({
  httpClient: vi.fn(),
}))

describe('useEndlessPreference', () => {
  beforeEach(() => {
    vi.clearAllMocks()
  })

  it('loads the backend preference into Redux', async () => {
    httpClient.mockResolvedValue({
      json: { endlessPlayback: true },
    })
    let hook
    const dispatch = vi.fn((action) => {
      hook.rerender({ endless: action.data.endless })
    })
    hook = renderHook(
      ({ endless }) =>
        useEndlessPreference({
          authenticated: true,
          dispatch,
          endless,
        }),
      { initialProps: { endless: false } },
    )

    await waitFor(() => expect(hook.result.current).toBe(true))

    expect(dispatch).toHaveBeenCalledWith({
      type: 'PLAYER_SET_ENDLESS',
      data: { endless: true },
    })
    expect(httpClient).toHaveBeenCalledTimes(1)
    expect(httpClient).toHaveBeenCalledWith('/api/user/preferences')
  })

  it('migrates the existing local value when the backend has no preference', async () => {
    httpClient
      .mockResolvedValueOnce({ json: { endlessPlayback: null } })
      .mockResolvedValue({})
    const dispatch = vi.fn()

    const { result } = renderHook(() =>
      useEndlessPreference({
        authenticated: true,
        dispatch,
        endless: true,
      }),
    )

    await act(async () => {
      await Promise.resolve()
      await Promise.resolve()
    })

    expect(result.current).toBe(true)
    expect(httpClient).toHaveBeenCalledTimes(2)
    expect(httpClient).toHaveBeenLastCalledWith('/api/user/preferences', {
      method: 'PUT',
      body: JSON.stringify({ endlessPlayback: true }),
    })
  })

  it('persists a toggle made while the backend preference is loading', async () => {
    let resolveLoad
    const load = new Promise((resolve) => {
      resolveLoad = resolve
    })
    httpClient.mockReturnValueOnce(load).mockResolvedValueOnce({})
    const dispatch = vi.fn()
    const hook = renderHook(
      ({ endless }) =>
        useEndlessPreference({
          authenticated: true,
          dispatch,
          endless,
        }),
      { initialProps: { endless: false } },
    )

    hook.rerender({ endless: true })
    await act(async () => {
      resolveLoad({ json: { endlessPlayback: false } })
      await load
    })

    await waitFor(() => expect(httpClient).toHaveBeenCalledTimes(2))
    expect(dispatch).not.toHaveBeenCalled()
    expect(httpClient).toHaveBeenLastCalledWith('/api/user/preferences', {
      method: 'PUT',
      body: JSON.stringify({ endlessPlayback: true }),
    })
  })

  it('writes rapid toggles in order so the latest value wins', async () => {
    let resolveFirstSave
    const firstSave = new Promise((resolve) => {
      resolveFirstSave = resolve
    })
    httpClient
      .mockResolvedValueOnce({ json: { endlessPlayback: false } })
      .mockReturnValueOnce(firstSave)
      .mockResolvedValueOnce({})
    const dispatch = vi.fn()
    const hook = renderHook(
      ({ endless }) =>
        useEndlessPreference({
          authenticated: true,
          dispatch,
          endless,
        }),
      { initialProps: { endless: false } },
    )

    await waitFor(() => expect(hook.result.current).toBe(true))

    hook.rerender({ endless: true })
    await waitFor(() => expect(httpClient).toHaveBeenCalledTimes(2))
    hook.rerender({ endless: false })

    await act(async () => {
      await Promise.resolve()
    })
    expect(httpClient).toHaveBeenCalledTimes(2)

    await act(async () => {
      resolveFirstSave({})
      await firstSave
    })
    await waitFor(() => expect(httpClient).toHaveBeenCalledTimes(3))

    expect(httpClient.mock.calls.slice(1)).toEqual([
      [
        '/api/user/preferences',
        {
          method: 'PUT',
          body: JSON.stringify({ endlessPlayback: true }),
        },
      ],
      [
        '/api/user/preferences',
        {
          method: 'PUT',
          body: JSON.stringify({ endlessPlayback: false }),
        },
      ],
    ])
  })

  it('keeps the local preference when the backend is unavailable', async () => {
    httpClient.mockRejectedValue(new Error('offline'))
    const dispatch = vi.fn()
    const { result } = renderHook(() =>
      useEndlessPreference({
        authenticated: true,
        dispatch,
        endless: true,
      }),
    )

    await waitFor(() => expect(result.current).toBe(true))

    expect(dispatch).not.toHaveBeenCalled()
    expect(httpClient).toHaveBeenCalledTimes(1)
  })
})
