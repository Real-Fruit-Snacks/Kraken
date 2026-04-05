import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, fireEvent } from '../../test/test-utils'
import { ConfirmModal, ConfirmModalWithInput, ErrorBanner } from '../ConfirmModal'

describe('ConfirmModal', () => {
  const defaultProps = {
    isOpen: true,
    title: 'Confirm Action',
    message: 'Are you sure you want to proceed?',
    onConfirm: vi.fn(),
    onCancel: vi.fn(),
  }

  beforeEach(() => {
    vi.clearAllMocks()
  })

  describe('rendering', () => {
    it('renders when isOpen is true', () => {
      render(<ConfirmModal {...defaultProps} />)
      expect(screen.getByText('Confirm Action')).toBeInTheDocument()
      expect(screen.getByText('Are you sure you want to proceed?')).toBeInTheDocument()
    })

    it('does not render when isOpen is false', () => {
      render(<ConfirmModal {...defaultProps} isOpen={false} />)
      expect(screen.queryByText('Confirm Action')).not.toBeInTheDocument()
    })

    it('renders default button text', () => {
      render(<ConfirmModal {...defaultProps} />)
      expect(screen.getByText('Confirm')).toBeInTheDocument()
      expect(screen.getByText('Cancel')).toBeInTheDocument()
    })

    it('renders custom button text', () => {
      render(
        <ConfirmModal
          {...defaultProps}
          confirmText="Delete"
          cancelText="Keep"
        />
      )
      expect(screen.getByText('Delete')).toBeInTheDocument()
      expect(screen.getByText('Keep')).toBeInTheDocument()
    })
  })

  describe('interactions', () => {
    it('calls onConfirm when confirm button is clicked', () => {
      render(<ConfirmModal {...defaultProps} />)
      fireEvent.click(screen.getByText('Confirm'))
      expect(defaultProps.onConfirm).toHaveBeenCalledTimes(1)
    })

    it('calls onCancel when cancel button is clicked', () => {
      render(<ConfirmModal {...defaultProps} />)
      fireEvent.click(screen.getByText('Cancel'))
      expect(defaultProps.onCancel).toHaveBeenCalledTimes(1)
    })

    it('calls onCancel when backdrop is clicked', () => {
      render(<ConfirmModal {...defaultProps} />)
      // Click the backdrop (parent div)
      const backdrop = screen.getByText('Confirm Action').closest('.fixed')
      if (backdrop) {
        fireEvent.click(backdrop)
        expect(defaultProps.onCancel).toHaveBeenCalledTimes(1)
      }
    })

    it('calls onCancel when Escape is pressed', () => {
      render(<ConfirmModal {...defaultProps} />)
      fireEvent.keyDown(document, { key: 'Escape' })
      expect(defaultProps.onCancel).toHaveBeenCalledTimes(1)
    })
  })

  describe('variants', () => {
    it('renders with danger variant', () => {
      render(<ConfirmModal {...defaultProps} variant="danger" />)
      expect(screen.getByText('Confirm Action')).toBeInTheDocument()
    })

    it('renders with warning variant', () => {
      render(<ConfirmModal {...defaultProps} variant="warning" />)
      expect(screen.getByText('Confirm Action')).toBeInTheDocument()
    })

    it('renders with default variant', () => {
      render(<ConfirmModal {...defaultProps} variant="default" />)
      expect(screen.getByText('Confirm Action')).toBeInTheDocument()
    })
  })
})

describe('ConfirmModalWithInput', () => {
  const defaultProps = {
    isOpen: true,
    title: 'Enter Value',
    message: 'Please provide a value',
    inputLabel: 'Value',
    onConfirm: vi.fn(),
    onCancel: vi.fn(),
  }

  beforeEach(() => {
    vi.clearAllMocks()
  })

  describe('rendering', () => {
    it('renders input field', () => {
      render(<ConfirmModalWithInput {...defaultProps} />)
      expect(screen.getByLabelText('Value')).toBeInTheDocument()
    })

    it('renders with default value', () => {
      render(
        <ConfirmModalWithInput {...defaultProps} inputDefault="default text" />
      )
      expect(screen.getByLabelText('Value')).toHaveValue('default text')
    })

    it('renders with placeholder', () => {
      render(
        <ConfirmModalWithInput
          {...defaultProps}
          inputPlaceholder="Enter something..."
        />
      )
      expect(screen.getByPlaceholderText('Enter something...')).toBeInTheDocument()
    })
  })

  describe('interactions', () => {
    it('updates input value on change', () => {
      render(<ConfirmModalWithInput {...defaultProps} />)
      const input = screen.getByLabelText('Value')
      fireEvent.change(input, { target: { value: 'new value' } })
      expect(input).toHaveValue('new value')
    })

    it('calls onConfirm with input value on submit', () => {
      render(<ConfirmModalWithInput {...defaultProps} />)
      const input = screen.getByLabelText('Value')
      fireEvent.change(input, { target: { value: 'test input' } })
      fireEvent.click(screen.getByText('Confirm'))
      expect(defaultProps.onConfirm).toHaveBeenCalledWith('test input')
    })

    it('submits form on Enter key', () => {
      render(<ConfirmModalWithInput {...defaultProps} />)
      const input = screen.getByLabelText('Value')
      fireEvent.change(input, { target: { value: 'enter test' } })
      fireEvent.submit(input.closest('form')!)
      expect(defaultProps.onConfirm).toHaveBeenCalledWith('enter test')
    })

    it('calls onCancel when cancel button is clicked', () => {
      render(<ConfirmModalWithInput {...defaultProps} />)
      fireEvent.click(screen.getByText('Cancel'))
      expect(defaultProps.onCancel).toHaveBeenCalledTimes(1)
    })

    it('calls onCancel when Escape is pressed', () => {
      render(<ConfirmModalWithInput {...defaultProps} />)
      fireEvent.keyDown(document, { key: 'Escape' })
      expect(defaultProps.onCancel).toHaveBeenCalledTimes(1)
    })
  })

  describe('reset on open', () => {
    it('resets input to default when reopened', () => {
      const { rerender } = render(
        <ConfirmModalWithInput {...defaultProps} inputDefault="initial" />
      )

      const input = screen.getByLabelText('Value')
      fireEvent.change(input, { target: { value: 'changed' } })
      expect(input).toHaveValue('changed')

      // Close and reopen
      rerender(<ConfirmModalWithInput {...defaultProps} inputDefault="initial" isOpen={false} />)
      rerender(<ConfirmModalWithInput {...defaultProps} inputDefault="initial" isOpen={true} />)

      expect(screen.getByLabelText('Value')).toHaveValue('initial')
    })
  })
})

describe('ErrorBanner', () => {
  it('renders error message', () => {
    render(<ErrorBanner message="Something went wrong" />)
    expect(screen.getByText('Something went wrong')).toBeInTheDocument()
  })

  it('renders dismiss button when onDismiss is provided', () => {
    const onDismiss = vi.fn()
    render(<ErrorBanner message="Error" onDismiss={onDismiss} />)
    expect(screen.getByLabelText('Dismiss')).toBeInTheDocument()
  })

  it('does not render dismiss button when onDismiss is not provided', () => {
    render(<ErrorBanner message="Error" />)
    expect(screen.queryByLabelText('Dismiss')).not.toBeInTheDocument()
  })

  it('calls onDismiss when dismiss button is clicked', () => {
    const onDismiss = vi.fn()
    render(<ErrorBanner message="Error" onDismiss={onDismiss} />)
    fireEvent.click(screen.getByLabelText('Dismiss'))
    expect(onDismiss).toHaveBeenCalledTimes(1)
  })
})
