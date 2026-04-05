import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, fireEvent } from '../../test/test-utils'
import { Modal } from '../Modal'

describe('Modal', () => {
  const defaultProps = {
    isOpen: true,
    onClose: vi.fn(),
    title: 'Test Modal',
    children: <div>Modal content</div>,
  }

  beforeEach(() => {
    vi.clearAllMocks()
  })

  describe('rendering', () => {
    it('renders when isOpen is true', () => {
      render(<Modal {...defaultProps} />)
      expect(screen.getByRole('dialog')).toBeInTheDocument()
      expect(screen.getByText('Test Modal')).toBeInTheDocument()
      expect(screen.getByText('Modal content')).toBeInTheDocument()
    })

    it('does not render when isOpen is false', () => {
      render(<Modal {...defaultProps} isOpen={false} />)
      expect(screen.queryByRole('dialog')).not.toBeInTheDocument()
    })

    it('renders title correctly', () => {
      render(<Modal {...defaultProps} title="Custom Title" />)
      expect(screen.getByText('Custom Title')).toBeInTheDocument()
    })

    it('renders children content', () => {
      render(
        <Modal {...defaultProps}>
          <p>Custom child content</p>
        </Modal>
      )
      expect(screen.getByText('Custom child content')).toBeInTheDocument()
    })

    it('renders footer when provided', () => {
      render(
        <Modal {...defaultProps} footer={<button>Footer Button</button>} />
      )
      expect(screen.getByText('Footer Button')).toBeInTheDocument()
    })

    it('does not render footer when not provided', () => {
      render(<Modal {...defaultProps} />)
      // No footer element should exist
      expect(screen.queryByText('Footer Button')).not.toBeInTheDocument()
    })
  })

  describe('close button', () => {
    it('shows close button by default', () => {
      render(<Modal {...defaultProps} />)
      expect(screen.getByLabelText('Close modal')).toBeInTheDocument()
    })

    it('hides close button when showCloseButton is false', () => {
      render(<Modal {...defaultProps} showCloseButton={false} />)
      expect(screen.queryByLabelText('Close modal')).not.toBeInTheDocument()
    })

    it('calls onClose when close button is clicked', () => {
      render(<Modal {...defaultProps} />)
      fireEvent.click(screen.getByLabelText('Close modal'))
      expect(defaultProps.onClose).toHaveBeenCalledTimes(1)
    })
  })

  describe('backdrop interaction', () => {
    it('calls onClose when backdrop is clicked', () => {
      render(<Modal {...defaultProps} />)
      fireEvent.click(screen.getByRole('dialog'))
      expect(defaultProps.onClose).toHaveBeenCalledTimes(1)
    })

    it('does not call onClose when modal content is clicked', () => {
      render(<Modal {...defaultProps} />)
      fireEvent.click(screen.getByText('Modal content'))
      expect(defaultProps.onClose).not.toHaveBeenCalled()
    })
  })

  describe('keyboard interaction', () => {
    it('calls onClose when Escape key is pressed', () => {
      render(<Modal {...defaultProps} />)
      fireEvent.keyDown(document, { key: 'Escape' })
      expect(defaultProps.onClose).toHaveBeenCalledTimes(1)
    })
  })

  describe('size variants', () => {
    it.each(['sm', 'md', 'lg', 'xl'] as const)(
      'renders with %s size',
      (size) => {
        render(<Modal {...defaultProps} size={size} />)
        expect(screen.getByRole('dialog')).toBeInTheDocument()
      }
    )

    it('defaults to md size', () => {
      render(<Modal {...defaultProps} />)
      // Modal renders, size is applied via className
      expect(screen.getByRole('dialog')).toBeInTheDocument()
    })
  })

  describe('accessibility', () => {
    it('has aria-modal attribute', () => {
      render(<Modal {...defaultProps} />)
      expect(screen.getByRole('dialog')).toHaveAttribute('aria-modal', 'true')
    })

    it('has aria-labelledby pointing to title', () => {
      render(<Modal {...defaultProps} />)
      expect(screen.getByRole('dialog')).toHaveAttribute(
        'aria-labelledby',
        'modal-title'
      )
    })

    it('title has correct id for aria-labelledby', () => {
      render(<Modal {...defaultProps} />)
      expect(screen.getByText('Test Modal')).toHaveAttribute('id', 'modal-title')
    })
  })
})
