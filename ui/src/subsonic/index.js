import { baseUrl } from '../utils'
import { httpClient } from '../dataProvider'

const url = (command, id, options) => {
  const username = localStorage.getItem('username')
  const token = localStorage.getItem('subsonic-token')
  const salt = localStorage.getItem('subsonic-salt')
  if (!username || !token || !salt) {
    return ''
  }

  const params = new URLSearchParams()
  params.append('u', username)
  params.append('t', token)
  params.append('s', salt)
  params.append('f', 'json')
  params.append('v', '1.8.0')
  params.append('c', 'NavidromeUI')
  id && params.append('id', id)
  if (options) {
    if (options.ts) {
      options['_'] = new Date().getTime()
      delete options.ts
    }
    Object.keys(options).forEach((k) => {
      params.append(k, options[k])
    })
  }
  return `/rest/${command}?${params.toString()}`
}

const ping = () => httpClient(url('ping'))

const scrobble = (id, time, submission = true, position = null) =>
  httpClient(
    url('scrobble', id, {
      ...(submission && time && { time }),
      submission,
      ...(!submission && position !== null && { position }),
    }),
  )

const nowPlaying = (id, position = null) => scrobble(id, null, false, position)

const star = (id) => httpClient(url('star', id))

const unstar = (id) => httpClient(url('unstar', id))

const setRating = (id, rating) => httpClient(url('setRating', id, { rating }))

const download = (id, format = 'raw', bitrate = '0') =>
  (window.location.href = baseUrl(url('download', id, { format, bitrate })))

const startScan = (options) => httpClient(url('startScan', null, options))

const getScanStatus = () => httpClient(url('getScanStatus'))

const getNowPlaying = () => httpClient(url('getNowPlaying'))

const getAvatarUrl = (username, size) =>
  baseUrl(
    url('getAvatar', null, {
      username,
      ...(size && { size }),
    }),
  )

const getCoverArtUrl = (record, size, square) => {
  const options = {
    ...(record.updatedAt && { _: record.updatedAt }),
    ...(size && { size }),
    ...(square && { square }),
  }

  // TODO Move this logic to server
  if (record.album) {
    return baseUrl(url('getCoverArt', 'mf-' + record.id, options))
  } else if (record.albumArtist) {
    return baseUrl(url('getCoverArt', 'al-' + record.id, options))
  } else if (record.sync !== undefined) {
    // This is a playlist
    return baseUrl(url('getCoverArt', 'pl-' + record.id, options))
  } else {
    return baseUrl(url('getCoverArt', 'ar-' + record.id, options))
  }
}

const getArtistInfo = (id) => {
  return httpClient(url('getArtistInfo', id))
}

const getAlbumInfo = (id) => {
  return httpClient(url('getAlbumInfo', id))
}

const getSimilarSongs2 = (id, count = 100) => {
  return httpClient(url('getSimilarSongs2', id, { count }))
}

const getTopSongs = (artist, count = 50) => {
  return httpClient(url('getTopSongs', null, { artist, count }))
}

const getRandomSongs = (size = 1) => {
  return httpClient(url('getRandomSongs', null, { size }))
}

const streamUrl = (id, options) => {
  return baseUrl(
    url('stream', id, {
      ts: true,
      ...options,
    }),
  )
}

export default {
  url,
  ping,
  scrobble,
  nowPlaying,
  download,
  star,
  unstar,
  setRating,
  startScan,
  getScanStatus,
  getNowPlaying,
  getCoverArtUrl,
  getAvatarUrl,
  streamUrl,
  getAlbumInfo,
  getArtistInfo,
  getTopSongs,
  getSimilarSongs2,
  getRandomSongs,
}
