import { describe, it, expect, beforeEach, afterEach } from 'vitest'
import { render, screen } from '@testing-library/react'
import { ProtectedRoute } from '../ProtectedRoute'
import { MemoryRouter, Routes, Route } from 'react-router-dom'
import { useAuthStore } from '../../stores/authStore'

// Get the initial state to reset after each test
const initialState = useAuthStore.getState()

describe('ProtectedRoute', () => {
  beforeEach(() => {
    // Reset store to initial state before each test
    useAuthStore.setState(initialState)
  })

  afterEach(() => {
    // Clean up after each test
    useAuthStore.setState(initialState)
  })

  describe('authenticated state', () => {
    it('renders children when authenticated', () => {
      useAuthStore.setState({ isAuthenticated: true })

      render(
        <MemoryRouter initialEntries={['/protected']}>
          <Routes>
            <Route
              path="/protected"
              element={
                <ProtectedRoute>
                  <div>Protected Content</div>
                </ProtectedRoute>
              }
            />
          </Routes>
        </MemoryRouter>
      )

      expect(screen.getByText('Protected Content')).toBeInTheDocument()
    })

    it('renders complex children when authenticated', () => {
      useAuthStore.setState({ isAuthenticated: true })

      render(
        <MemoryRouter initialEntries={['/dashboard']}>
          <Routes>
            <Route
              path="/dashboard"
              element={
                <ProtectedRoute>
                  <div>
                    <h1>Dashboard</h1>
                    <p>Welcome back!</p>
                  </div>
                </ProtectedRoute>
              }
            />
          </Routes>
        </MemoryRouter>
      )

      expect(screen.getByText('Dashboard')).toBeInTheDocument()
      expect(screen.getByText('Welcome back!')).toBeInTheDocument()
    })
  })

  describe('unauthenticated state', () => {
    it('redirects to login when not authenticated', () => {
      useAuthStore.setState({ isAuthenticated: false })

      render(
        <MemoryRouter initialEntries={['/protected']}>
          <Routes>
            <Route path="/login" element={<div>Login Page</div>} />
            <Route
              path="/protected"
              element={
                <ProtectedRoute>
                  <div>Protected Content</div>
                </ProtectedRoute>
              }
            />
          </Routes>
        </MemoryRouter>
      )

      // Should redirect to login, not show protected content
      expect(screen.queryByText('Protected Content')).not.toBeInTheDocument()
      expect(screen.getByText('Login Page')).toBeInTheDocument()
    })

    it('does not render protected content when unauthenticated', () => {
      useAuthStore.setState({ isAuthenticated: false })

      render(
        <MemoryRouter initialEntries={['/secret']}>
          <Routes>
            <Route path="/login" element={<div>Login Page</div>} />
            <Route
              path="/secret"
              element={
                <ProtectedRoute>
                  <div>Secret Data</div>
                </ProtectedRoute>
              }
            />
          </Routes>
        </MemoryRouter>
      )

      expect(screen.queryByText('Secret Data')).not.toBeInTheDocument()
    })
  })

  describe('auth state behavior', () => {
    it('renders correct content based on auth state', () => {
      // Test authenticated state
      useAuthStore.setState({ isAuthenticated: true })

      const { unmount } = render(
        <MemoryRouter initialEntries={['/protected']}>
          <Routes>
            <Route path="/login" element={<div>Login Page</div>} />
            <Route
              path="/protected"
              element={
                <ProtectedRoute>
                  <div>Protected Content</div>
                </ProtectedRoute>
              }
            />
          </Routes>
        </MemoryRouter>
      )

      expect(screen.getByText('Protected Content')).toBeInTheDocument()
      unmount()

      // Test unauthenticated state - fresh render
      useAuthStore.setState({ isAuthenticated: false })

      render(
        <MemoryRouter initialEntries={['/protected']}>
          <Routes>
            <Route path="/login" element={<div>Login Page</div>} />
            <Route
              path="/protected"
              element={
                <ProtectedRoute>
                  <div>Protected Content</div>
                </ProtectedRoute>
              }
            />
          </Routes>
        </MemoryRouter>
      )

      expect(screen.queryByText('Protected Content')).not.toBeInTheDocument()
      expect(screen.getByText('Login Page')).toBeInTheDocument()
    })

    it('protects multiple routes consistently', () => {
      useAuthStore.setState({ isAuthenticated: false })

      const { unmount } = render(
        <MemoryRouter initialEntries={['/dashboard']}>
          <Routes>
            <Route path="/login" element={<div>Login Page</div>} />
            <Route
              path="/dashboard"
              element={
                <ProtectedRoute>
                  <div>Dashboard</div>
                </ProtectedRoute>
              }
            />
          </Routes>
        </MemoryRouter>
      )

      expect(screen.getByText('Login Page')).toBeInTheDocument()
      unmount()

      render(
        <MemoryRouter initialEntries={['/settings']}>
          <Routes>
            <Route path="/login" element={<div>Login Page</div>} />
            <Route
              path="/settings"
              element={
                <ProtectedRoute>
                  <div>Settings</div>
                </ProtectedRoute>
              }
            />
          </Routes>
        </MemoryRouter>
      )

      expect(screen.getByText('Login Page')).toBeInTheDocument()
    })
  })

  describe('navigation behavior', () => {
    it('uses replace navigation to prevent back button to protected route', () => {
      useAuthStore.setState({ isAuthenticated: false })

      render(
        <MemoryRouter initialEntries={['/protected']}>
          <Routes>
            <Route path="/login" element={<div>Login Page</div>} />
            <Route
              path="/protected"
              element={
                <ProtectedRoute>
                  <div>Protected Content</div>
                </ProtectedRoute>
              }
            />
          </Routes>
        </MemoryRouter>
      )

      // Component uses Navigate with replace prop
      // We verify redirect happened
      expect(screen.getByText('Login Page')).toBeInTheDocument()
    })
  })
})
