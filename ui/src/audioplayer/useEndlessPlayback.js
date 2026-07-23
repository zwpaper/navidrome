import { useEffect, useRef, useState } from 'react'
import { addTracks } from '../actions'
import subsonic from '../subsonic'

export const ENDLESS_BUFFER_SIZE = 3
export const ENDLESS_RETRY_DELAY_MS = 5000

export const getEndlessPlayMode = (enabled, playMode) => {
  const normalPlayMode = playMode || 'order'
  return enabled && normalPlayMode === 'order' ? 'orderLoop' : normalPlayMode
}

export const extractRandomSongs = (response) => {
  const songs = response?.json?.['subsonic-response']?.randomSongs?.song || []
  return Array.isArray(songs) ? songs : [songs]
}

const toTrackMap = (songs) =>
  songs.reduce((tracks, song, index) => {
    if (song?.id) {
      // The action only needs an ordered object. Including the index keeps
      // repeated results playable as separate queue entries.
      tracks[`${song.id}:${index}`] = song
    }
    return tracks
  }, {})

/**
 * Keeps a small buffer of random songs after the current track.
 *
 * Refilling is driven by queue state instead of audio progress callbacks, so
 * enabling endless play halfway through a track works as well. Requests remain
 * valid when playback advances, but are ignored if the originating queue was
 * replaced.
 */
export const useEndlessPlayback = ({ current, dispatch, enabled, queue }) => {
  const [requestVersion, setRequestVersion] = useState(0)
  const requestInFlightRef = useRef(false)
  const retryTimeoutRef = useRef(null)
  const mountedRef = useRef(true)
  const latestStateRef = useRef({ enabled, queue })
  latestStateRef.current = { enabled, queue }

  const currentUuid = current?.uuid
  const currentIndex = currentUuid
    ? queue.findIndex((item) => item.uuid === currentUuid)
    : -1
  const tracksRemaining =
    currentIndex >= 0 ? queue.length - currentIndex - 1 : Infinity
  const currentIsRadio =
    current?.isRadio || (currentIndex >= 0 && queue[currentIndex]?.isRadio)

  useEffect(() => {
    mountedRef.current = true
    return () => {
      mountedRef.current = false
      if (retryTimeoutRef.current) {
        clearTimeout(retryTimeoutRef.current)
      }
    }
  }, [])

  useEffect(() => {
    const needsRefill =
      enabled &&
      !currentIsRadio &&
      currentIndex >= 0 &&
      tracksRemaining < ENDLESS_BUFFER_SIZE

    if (!needsRefill) {
      if (retryTimeoutRef.current) {
        clearTimeout(retryTimeoutRef.current)
        retryTimeoutRef.current = null
      }
      return
    }

    if (requestInFlightRef.current) {
      return
    }

    // A track change is a useful opportunity to retry immediately.
    if (retryTimeoutRef.current) {
      clearTimeout(retryTimeoutRef.current)
      retryTimeoutRef.current = null
    }

    const requestedByUuid = currentUuid
    const requestSize = ENDLESS_BUFFER_SIZE - tracksRemaining
    requestInFlightRef.current = true

    const refill = async () => {
      let shouldRetry = false
      let shouldReevaluate = false

      try {
        const response = await subsonic.getRandomSongs(requestSize)
        const tracks = toTrackMap(extractRandomSongs(response))
        const latestState = latestStateRef.current
        const originatingQueueIsActive = latestState.queue.some(
          (item) => item.uuid === requestedByUuid,
        )

        if (!latestState.enabled || !originatingQueueIsActive) {
          shouldReevaluate = true
          return
        }

        if (Object.keys(tracks).length === 0) {
          shouldRetry = true
          return
        }

        // Append without replacing the player's internal list. Replacing the
        // list here can pause/reset the audio element before the song ends.
        dispatch(addTracks(tracks))
      } catch (error) {
        shouldRetry = true
        // eslint-disable-next-line no-console
        console.error('Error refilling endless playback queue:', error)
      } finally {
        requestInFlightRef.current = false
        if (mountedRef.current) {
          if (shouldRetry && latestStateRef.current.enabled) {
            retryTimeoutRef.current = setTimeout(() => {
              retryTimeoutRef.current = null
              if (mountedRef.current) {
                setRequestVersion((version) => version + 1)
              }
            }, ENDLESS_RETRY_DELAY_MS)
          } else if (shouldReevaluate) {
            // Re-evaluate if the queue or current track changed while the
            // request was in flight and the response was intentionally ignored.
            setRequestVersion((version) => version + 1)
          }
        }
      }
    }

    refill()
  }, [
    currentIndex,
    currentIsRadio,
    currentUuid,
    dispatch,
    enabled,
    requestVersion,
    tracksRemaining,
  ])
}
