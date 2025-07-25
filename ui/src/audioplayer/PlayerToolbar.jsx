import React, { useCallback } from 'react'
import { useDispatch, useSelector } from 'react-redux'
import { useGetOne } from 'react-admin'
import { GlobalHotKeys } from 'react-hotkeys'
import IconButton from '@material-ui/core/IconButton'
import { useMediaQuery } from '@material-ui/core'
import { RiSaveLine, RiInfinityLine } from 'react-icons/ri'
import { LoveButton, useToggleLove } from '../common'
import { openSaveQueueDialog, setEndless } from '../actions'
import { keyMap } from '../hotkeys'
import { makeStyles } from '@material-ui/core/styles'

const useStyles = makeStyles((theme) => ({
  toolbar: {
    display: 'flex',
    alignItems: 'center',
    flexGrow: 1,
    justifyContent: 'flex-end',
    gap: '0.5rem',
    listStyle: 'none',
    padding: 0,
    margin: 0,
  },
  mobileListItem: {
    display: 'flex',
    alignItems: 'center',
    justifyContent: 'center',
    listStyle: 'none',
    padding: theme.spacing(0.5),
    margin: 0,
    height: 24,
  },
  button: {
    width: '2.5rem',
    height: '2.5rem',
    display: 'flex',
    alignItems: 'center',
    justifyContent: 'center',
    padding: 0,
  },
  endlessButton: {
    width: '2.5rem',
    height: '2.5rem',
    display: 'flex',
    alignItems: 'center',
    justifyContent: 'center',
    padding: 0,
  },
  mobileButton: {
    width: 24,
    height: 24,
    padding: 0,
    margin: 0,
    display: 'flex',
    alignItems: 'center',
    justifyContent: 'center',
    fontSize: '18px',
  },
  mobileIcon: {
    fontSize: '18px',
    display: 'flex',
    alignItems: 'center',
  },
}))

const PlayerToolbar = ({ id, isRadio }) => {
  const dispatch = useDispatch()
  const { data, loading } = useGetOne('song', id, { enabled: !!id && !isRadio })
  const [toggleLove, toggling] = useToggleLove('song', data)
  const isDesktop = useMediaQuery('(min-width:810px)')
  const classes = useStyles()
  const endless = useSelector((state) => state.player.endless)

  const handlers = {
    TOGGLE_LOVE: useCallback(() => toggleLove(), [toggleLove]),
  }

  const handleSaveQueue = useCallback(
    (e) => {
      dispatch(openSaveQueueDialog())
      e.stopPropagation()
    },
    [dispatch],
  )

  const handleToggleEndless = useCallback(
    (e) => {
      dispatch(setEndless(!endless))
      e.stopPropagation()
    },
    [dispatch, endless],
  )

  const buttonClass = isDesktop ? classes.button : classes.mobileButton
  const listItemClass = isDesktop ? classes.toolbar : classes.mobileListItem

  const saveQueueButton = (
    <IconButton
      size={isDesktop ? 'small' : undefined}
      onClick={handleSaveQueue}
      disabled={isRadio}
      data-testid="save-queue-button"
      className={buttonClass}
    >
      <RiSaveLine className={!isDesktop ? classes.mobileIcon : undefined} />
    </IconButton>
  )

  const loveButton = (
    <LoveButton
      record={data}
      resource={'song'}
      size={isDesktop ? undefined : 'inherit'}
      disabled={loading || toggling || !id || isRadio}
      className={buttonClass}
    />
  )

  const endlessButton = (
    <IconButton
      size={isDesktop ? 'small' : undefined}
      onClick={handleToggleEndless}
      data-testid="endless-play-button"
      className={isDesktop ? classes.endlessButton : classes.mobileButton}
      style={{
        color: endless ? '#1976d2' : '#9e9e9e',
      }}
      title={endless ? 'Disable endless play' : 'Enable endless play'}
    >
      <RiInfinityLine className={!isDesktop ? classes.mobileIcon : undefined} />
    </IconButton>
  )

  return (
    <>
      <GlobalHotKeys keyMap={keyMap} handlers={handlers} allowChanges />
      {isDesktop ? (
        <li className={`${listItemClass} item`}>
          {saveQueueButton}
          {endlessButton}
          {loveButton}
        </li>
      ) : (
        <>
          <li className={`${listItemClass} item`}>{saveQueueButton}</li>
          <li className={`${listItemClass} item`}>{endlessButton}</li>
          <li className={`${listItemClass} item`}>{loveButton}</li>
        </>
      )}
    </>
  )
}

export default PlayerToolbar
