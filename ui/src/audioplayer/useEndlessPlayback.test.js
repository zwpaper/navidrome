import { act, renderHook } from '@testing-library/react-hooks'
import { waitFor } from '@testing-library/react'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import { PLAYER_ADD_TRACKS } from '../actions'
import subsonic from '../subsonic'
import {
  ENDLESS_BUFFER_SIZE,
  ENDLESS_RETRY_DELAY_MS,
  extractRandomSongs,
  getEndlessPlayMode,
  useEndlessPlayback,
} from './useEndlessPlayback'

vi.mock('../subsonic', () => ({
  default: {
    getRandomSongs: vi.fn(),
  },
}))

const randomSongsResponse = (songs) => ({
  json: {
    'subsonic-response': {
      randomSongs: { song: songs },
    },
  },
})

const queueItem = (id) => ({
  trackId: id,
  uuid: `${id}-uuid`,
  song: { id, title: id },
})

describe('useEndlessPlayback', () => {
  beforeEach(() => {
    vi.clearAllMocks()
  })

  it('keeps order playback unchanged when disabled and loops it as a safety net when enabled', () => {
    expect(getEndlessPlayMode(false)).toBe('order')
    expect(getEndlessPlayMode(false, 'order')).toBe('order')
    expect(getEndlessPlayMode(true, 'order')).toBe('orderLoop')
    expect(getEndlessPlayMode(true, 'shufflePlay')).toBe('shufflePlay')
    expect(getEndlessPlayMode(true, 'singleLoop')).toBe('singleLoop')
  })

  it('extracts both array and singleton Subsonic responses', () => {
    const song = { id: 'random-1' }
    expect(extractRandomSongs(randomSongsResponse([song]))).toEqual([song])
    expect(extractRandomSongs(randomSongsResponse(song))).toEqual([song])
    expect(extractRandomSongs({})).toEqual([])
  })

  it('does nothing when endless playback is disabled', () => {
    const current = queueItem('current')

    renderHook(() =>
      useEndlessPlayback({
        current,
        dispatch: vi.fn(),
        enabled: false,
        queue: [current],
      }),
    )

    expect(subsonic.getRandomSongs).not.toHaveBeenCalled()
  })

  it('does not refill while the configured buffer is already available', () => {
    const current = queueItem('current')
    const queue = [
      current,
      ...Array.from({ length: ENDLESS_BUFFER_SIZE }, (_, index) =>
        queueItem(`next-${index}`),
      ),
    ]

    renderHook(() =>
      useEndlessPlayback({
        current,
        dispatch: vi.fn(),
        enabled: true,
        queue,
      }),
    )

    expect(subsonic.getRandomSongs).not.toHaveBeenCalled()
  })

  it('appends enough random songs to fill the buffer without replacing the queue', async () => {
    const current = queueItem('current')
    const next = queueItem('next')
    const dispatch = vi.fn()
    const randomSongs = [
      { id: 'random-1', title: 'Random one' },
      { id: 'random-2', title: 'Random two' },
    ]
    subsonic.getRandomSongs.mockResolvedValue(randomSongsResponse(randomSongs))

    renderHook(() =>
      useEndlessPlayback({
        current,
        dispatch,
        enabled: true,
        queue: [current, next],
      }),
    )

    expect(subsonic.getRandomSongs).toHaveBeenCalledWith(2)
    await waitFor(() => expect(dispatch).toHaveBeenCalledTimes(1))

    const action = dispatch.mock.calls[0][0]
    expect(action.type).toBe(PLAYER_ADD_TRACKS)
    expect(Object.values(action.data)).toEqual(randomSongs)
  })

  it('retries when the random endpoint temporarily returns no songs', async () => {
    vi.useFakeTimers()
    const current = queueItem('current')
    const dispatch = vi.fn()
    const recoveredSongs = [
      { id: 'random-1', title: 'Random one' },
      { id: 'random-2', title: 'Random two' },
      { id: 'random-3', title: 'Random three' },
    ]
    subsonic.getRandomSongs
      .mockResolvedValueOnce(randomSongsResponse([]))
      .mockResolvedValueOnce(randomSongsResponse(recoveredSongs))

    try {
      renderHook(() =>
        useEndlessPlayback({
          current,
          dispatch,
          enabled: true,
          queue: [current],
        }),
      )

      await act(async () => {
        await Promise.resolve()
      })
      expect(subsonic.getRandomSongs).toHaveBeenCalledTimes(1)
      expect(dispatch).not.toHaveBeenCalled()

      await act(async () => {
        await vi.advanceTimersByTimeAsync(ENDLESS_RETRY_DELAY_MS)
      })

      expect(subsonic.getRandomSongs).toHaveBeenCalledTimes(2)
      expect(dispatch).toHaveBeenCalledTimes(1)
      expect(Object.values(dispatch.mock.calls[0][0].data)).toEqual(
        recoveredSongs,
      )
    } finally {
      vi.useRealTimers()
    }
  })

  it('ignores a refill from a replaced queue and refills the active queue', async () => {
    let resolveFirstRequest
    const firstRequest = new Promise((resolve) => {
      resolveFirstRequest = resolve
    })
    subsonic.getRandomSongs
      .mockReturnValueOnce(firstRequest)
      .mockResolvedValueOnce(
        randomSongsResponse([{ id: 'new-random', title: 'New random' }]),
      )

    const oldCurrent = queueItem('old-current')
    const newCurrent = queueItem('new-current')
    const dispatch = vi.fn()
    const { rerender } = renderHook(
      ({ current, queue }) =>
        useEndlessPlayback({
          current,
          dispatch,
          enabled: true,
          queue,
        }),
      {
        initialProps: {
          current: oldCurrent,
          queue: [oldCurrent],
        },
      },
    )

    rerender({ current: newCurrent, queue: [newCurrent] })
    await act(async () => {
      resolveFirstRequest(
        randomSongsResponse([{ id: 'old-random', title: 'Old random' }]),
      )
      await firstRequest
    })

    await waitFor(() =>
      expect(subsonic.getRandomSongs).toHaveBeenCalledTimes(2),
    )
    await waitFor(() => expect(dispatch).toHaveBeenCalledTimes(1))
    expect(Object.values(dispatch.mock.calls[0][0].data)).toEqual([
      { id: 'new-random', title: 'New random' },
    ])
  })
})
