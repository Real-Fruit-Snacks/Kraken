import { describe, it, expect, vi } from 'vitest'
import { render, screen, fireEvent } from '../../test/test-utils'
import { KeyboardShortcutsModal } from '../KeyboardShortcutsModal'

describe('KeyboardShortcutsModal', () => {
  const defaultProps = {
    isOpen: true,
    onClose: vi.fn(),
  }

  describe('rendering', () => {
    it('renders when isOpen is true', () => {
      render(<KeyboardShortcutsModal {...defaultProps} />)
      expect(screen.getByText('Keyboard Shortcuts')).toBeInTheDocument()
    })

    it('does not render when isOpen is false', () => {
      render(<KeyboardShortcutsModal {...defaultProps} isOpen={false} />)
      expect(screen.queryByText('Keyboard Shortcuts')).not.toBeInTheDocument()
    })

    it('renders all shortcut group titles', () => {
      render(<KeyboardShortcutsModal {...defaultProps} />)
      expect(screen.getByText('Global')).toBeInTheDocument()
      expect(screen.getByText('Navigation')).toBeInTheDocument()
      expect(screen.getByText('Session Actions')).toBeInTheDocument()
      expect(screen.getByText('Quick Actions')).toBeInTheDocument()
      expect(screen.getByText('Command Palette')).toBeInTheDocument()
      expect(screen.getByText('Tables & Lists')).toBeInTheDocument()
      expect(screen.getByText('Collaboration')).toBeInTheDocument()
    })
  })

  describe('global shortcuts', () => {
    it('displays command palette shortcut', () => {
      render(<KeyboardShortcutsModal {...defaultProps} />)
      expect(screen.getByText('Open Command Palette')).toBeInTheDocument()
      // Multiple Ctrl and K keys exist for different shortcuts
      expect(screen.getAllByText('Ctrl').length).toBeGreaterThan(0)
      expect(screen.getAllByText('K').length).toBeGreaterThan(0)
    })

    it('displays keyboard shortcuts help shortcut', () => {
      render(<KeyboardShortcutsModal {...defaultProps} />)
      expect(screen.getByText('Show Keyboard Shortcuts')).toBeInTheDocument()
    })

    it('displays escape shortcut', () => {
      render(<KeyboardShortcutsModal {...defaultProps} />)
      expect(screen.getByText('Close modal / Cancel action')).toBeInTheDocument()
      // Multiple Esc keys rendered, just check at least one exists
      expect(screen.getAllByText('Esc').length).toBeGreaterThan(0)
    })
  })

  describe('navigation shortcuts', () => {
    it('displays go to dashboard shortcut', () => {
      render(<KeyboardShortcutsModal {...defaultProps} />)
      expect(screen.getByText('Go to Dashboard')).toBeInTheDocument()
    })

    it('displays go to sessions shortcut', () => {
      render(<KeyboardShortcutsModal {...defaultProps} />)
      expect(screen.getByText('Go to Sessions')).toBeInTheDocument()
    })

    it('displays go to listeners shortcut', () => {
      render(<KeyboardShortcutsModal {...defaultProps} />)
      expect(screen.getByText('Go to Listeners')).toBeInTheDocument()
    })

    it('displays go to topology shortcut', () => {
      render(<KeyboardShortcutsModal {...defaultProps} />)
      expect(screen.getByText('Go to Topology')).toBeInTheDocument()
    })

    it('displays go to defender view shortcut', () => {
      render(<KeyboardShortcutsModal {...defaultProps} />)
      expect(screen.getByText('Go to Defender View')).toBeInTheDocument()
    })

    it('displays go to loot shortcut', () => {
      render(<KeyboardShortcutsModal {...defaultProps} />)
      expect(screen.getByText('Go to Loot')).toBeInTheDocument()
    })

    it('displays go to modules shortcut', () => {
      render(<KeyboardShortcutsModal {...defaultProps} />)
      expect(screen.getByText('Go to Modules')).toBeInTheDocument()
    })

    it('displays go to operators shortcut', () => {
      render(<KeyboardShortcutsModal {...defaultProps} />)
      expect(screen.getByText('Go to Operators')).toBeInTheDocument()
    })

    it('displays go to reports shortcut', () => {
      render(<KeyboardShortcutsModal {...defaultProps} />)
      expect(screen.getByText('Go to Reports')).toBeInTheDocument()
    })
  })

  describe('session action shortcuts', () => {
    it('displays execute command shortcut', () => {
      render(<KeyboardShortcutsModal {...defaultProps} />)
      expect(screen.getByText('Execute command')).toBeInTheDocument()
    })

    it('displays upload file shortcut', () => {
      render(<KeyboardShortcutsModal {...defaultProps} />)
      expect(screen.getByText('Upload file to session')).toBeInTheDocument()
    })

    it('displays download file shortcut', () => {
      render(<KeyboardShortcutsModal {...defaultProps} />)
      expect(screen.getByText('Download file from session')).toBeInTheDocument()
    })

    it('displays autocomplete shortcut', () => {
      render(<KeyboardShortcutsModal {...defaultProps} />)
      expect(screen.getByText('Autocomplete command')).toBeInTheDocument()
    })

    it('displays command history navigation shortcuts', () => {
      render(<KeyboardShortcutsModal {...defaultProps} />)
      expect(screen.getByText('Previous command in history')).toBeInTheDocument()
      expect(screen.getByText('Next command in history')).toBeInTheDocument()
    })

    it('displays cancel operation shortcut', () => {
      render(<KeyboardShortcutsModal {...defaultProps} />)
      expect(screen.getByText('Cancel current operation')).toBeInTheDocument()
    })

    it('displays clear terminal shortcut', () => {
      render(<KeyboardShortcutsModal {...defaultProps} />)
      expect(screen.getByText('Clear terminal output')).toBeInTheDocument()
    })
  })

  describe('quick action shortcuts', () => {
    it('displays create listener shortcut', () => {
      render(<KeyboardShortcutsModal {...defaultProps} />)
      expect(screen.getByText('Create new listener')).toBeInTheDocument()
    })

    it('displays generate payload shortcut', () => {
      render(<KeyboardShortcutsModal {...defaultProps} />)
      expect(screen.getByText('Generate payload')).toBeInTheDocument()
    })

    it('displays new session tab shortcut', () => {
      render(<KeyboardShortcutsModal {...defaultProps} />)
      expect(screen.getByText('New session tab')).toBeInTheDocument()
    })

    it('displays close tab shortcut', () => {
      render(<KeyboardShortcutsModal {...defaultProps} />)
      expect(screen.getByText('Close current tab')).toBeInTheDocument()
    })
  })

  describe('table navigation shortcuts', () => {
    it('displays next/previous row shortcuts', () => {
      render(<KeyboardShortcutsModal {...defaultProps} />)
      expect(screen.getByText('Next row')).toBeInTheDocument()
      expect(screen.getByText('Previous row')).toBeInTheDocument()
    })

    it('displays open selected item shortcut', () => {
      render(<KeyboardShortcutsModal {...defaultProps} />)
      expect(screen.getByText('Open selected item')).toBeInTheDocument()
    })

    it('displays focus search shortcut', () => {
      render(<KeyboardShortcutsModal {...defaultProps} />)
      expect(screen.getByText('Focus search / filter')).toBeInTheDocument()
    })
  })

  describe('collaboration shortcuts', () => {
    it('displays toggle collaboration panel shortcut', () => {
      render(<KeyboardShortcutsModal {...defaultProps} />)
      expect(screen.getByText('Toggle collaboration panel')).toBeInTheDocument()
    })

    it('displays send chat message shortcut', () => {
      render(<KeyboardShortcutsModal {...defaultProps} />)
      expect(screen.getByText('Send chat message')).toBeInTheDocument()
    })
  })

  describe('footer help text', () => {
    it('displays help footer text', () => {
      render(<KeyboardShortcutsModal {...defaultProps} />)
      expect(screen.getByText(/anywhere to show this help/)).toBeInTheDocument()
    })
  })

  describe('interactions', () => {
    it('calls onClose when modal is closed', () => {
      const onClose = vi.fn()
      render(<KeyboardShortcutsModal isOpen={true} onClose={onClose} />)

      // Click close button
      fireEvent.click(screen.getByLabelText('Close modal'))
      expect(onClose).toHaveBeenCalledTimes(1)
    })

    it('calls onClose when Escape is pressed', () => {
      const onClose = vi.fn()
      render(<KeyboardShortcutsModal isOpen={true} onClose={onClose} />)

      fireEvent.keyDown(document, { key: 'Escape' })
      expect(onClose).toHaveBeenCalledTimes(1)
    })
  })

  describe('keyboard key rendering', () => {
    it('renders kbd elements with proper styling', () => {
      render(<KeyboardShortcutsModal {...defaultProps} />)

      // Check that kbd elements exist
      const kbdElements = document.querySelectorAll('kbd')
      expect(kbdElements.length).toBeGreaterThan(0)
    })

    it('renders multi-key shortcuts with plus separator', () => {
      render(<KeyboardShortcutsModal {...defaultProps} />)

      // Look for the '+' separator between keys
      const plusSeparators = screen.getAllByText('+')
      expect(plusSeparators.length).toBeGreaterThan(0)
    })
  })

  describe('accessibility', () => {
    it('modal has proper dialog role', () => {
      render(<KeyboardShortcutsModal {...defaultProps} />)
      expect(screen.getByRole('dialog')).toBeInTheDocument()
    })

    it('shortcut groups have proper heading structure', () => {
      render(<KeyboardShortcutsModal {...defaultProps} />)

      // h3 elements for group titles
      const headings = document.querySelectorAll('h3')
      expect(headings.length).toBe(7) // 7 shortcut groups
    })
  })
})
