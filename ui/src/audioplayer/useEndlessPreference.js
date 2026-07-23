import { useEffect, useRef, useState } from 'react'
import { setEndless } from '../actions'
import { httpClient } from '../dataProvider'

const preferencesEndpoint = '/api/user/preferences'

const saveEndlessPreference = (endlessPlayback) =>
  httpClient(preferencesEndpoint, {
    method: 'PUT',
    body: JSON.stringify({ endlessPlayback }),
  })

/**
 * Loads endless playback from the current user's backend preferences, then
 * keeps subsequent Redux changes synchronized. localStorage remains the
 * fallback when the server cannot be reached.
 */
export const useEndlessPreference = ({ authenticated, dispatch, endless }) => {
  const [ready, setReady] = useState(false)
  const endlessRef = useRef(endless)
  const savedRemoteValueRef = useRef()
  const saveQueueRef = useRef(Promise.resolve())
  const preferenceSessionRef = useRef(0)
  endlessRef.current = endless

  useEffect(() => {
    let cancelled = false
    const session = preferenceSessionRef.current + 1
    preferenceSessionRef.current = session
    setReady(false)
    savedRemoteValueRef.current = undefined

    if (!authenticated) {
      return () => {
        cancelled = true
        if (preferenceSessionRef.current === session) {
          preferenceSessionRef.current += 1
        }
      }
    }

    const localValueAtStart = endlessRef.current
    httpClient(preferencesEndpoint)
      .then((response) => {
        if (cancelled) {
          return
        }

        const remoteValue = response.json?.endlessPlayback
        savedRemoteValueRef.current = remoteValue

        // Do not overwrite a toggle made while this request was in flight.
        if (
          typeof remoteValue === 'boolean' &&
          endlessRef.current === localValueAtStart
        ) {
          dispatch(setEndless(remoteValue))
        }
        // A null/absent value intentionally falls through to the save effect,
        // migrating the browser's existing preference to the backend.
        setReady(true)
      })
      .catch(() => {
        if (!cancelled) {
          // Preserve local behavior when talking to an older/offline server.
          savedRemoteValueRef.current = endlessRef.current
          setReady(true)
        }
      })

    return () => {
      cancelled = true
      if (preferenceSessionRef.current === session) {
        preferenceSessionRef.current += 1
      }
    }
  }, [authenticated, dispatch])

  useEffect(() => {
    if (!authenticated || !ready || savedRemoteValueRef.current === endless) {
      return
    }

    const value = endless
    const session = preferenceSessionRef.current
    savedRemoteValueRef.current = value
    saveQueueRef.current = saveQueueRef.current.then(async () => {
      if (preferenceSessionRef.current !== session) {
        return
      }

      try {
        await saveEndlessPreference(value)
      } catch (error) {
        // Keep the local value and allow the next toggle/session to retry.
        if (savedRemoteValueRef.current === value) {
          savedRemoteValueRef.current = undefined
        }
        // eslint-disable-next-line no-console
        console.error('Error saving endless playback preference:', error)
      }
    })
  }, [authenticated, endless, ready])

  return ready
}
