import { useState, type FormEvent } from 'react';
import { useNavigate } from 'react-router-dom';
import { useAuthStore } from '../stores/authStore';

export function Login() {
  const [token, setToken] = useState('');
  const [error, setError] = useState('');
  const login = useAuthStore((s) => s.login);
  const navigate = useNavigate();

  const handleSubmit = (e: FormEvent) => {
    e.preventDefault();
    const trimmed = token.trim();
    if (!trimmed) {
      setError('Token is required.');
      return;
    }
    login(trimmed);
    navigate('/dashboard', { replace: true });
  };

  return (
    <div
      className="min-h-screen flex items-center justify-center"
      style={{ backgroundColor: 'var(--ctp-base)' }}
    >
      <div
        className="w-full max-w-md rounded-xl p-8 shadow-2xl"
        style={{ backgroundColor: 'var(--ctp-mantle)', border: '1px solid var(--ctp-surface0)' }}
      >
        {/* Logo / Title */}
        <div className="mb-8 text-center">
          <div className="mb-3 flex items-center justify-center">
            <svg
              className="h-12 w-12"
              viewBox="0 0 64 64"
              fill="none"
              xmlns="http://www.w3.org/2000/svg"
            >
              <circle cx="32" cy="32" r="30" stroke="var(--ctp-mauve)" strokeWidth="2" />
              {/* Stylised kraken tentacle motif */}
              <path
                d="M32 12 C24 20 20 28 24 36 C28 44 36 44 40 36 C44 28 40 20 32 12Z"
                fill="var(--ctp-mauve)"
                opacity="0.3"
              />
              <circle cx="32" cy="32" r="6" fill="var(--ctp-mauve)" />
              <path d="M32 38 C28 46 20 50 16 52" stroke="var(--ctp-mauve)" strokeWidth="2" strokeLinecap="round" />
              <path d="M32 38 C36 46 44 50 48 52" stroke="var(--ctp-mauve)" strokeWidth="2" strokeLinecap="round" />
              <path d="M32 38 C30 48 28 52 24 56" stroke="var(--ctp-mauve)" strokeWidth="2" strokeLinecap="round" />
              <path d="M32 38 C34 48 36 52 40 56" stroke="var(--ctp-mauve)" strokeWidth="2" strokeLinecap="round" />
            </svg>
          </div>
          <h1
            className="text-3xl font-bold tracking-widest uppercase"
            style={{ color: 'var(--ctp-mauve)' }}
          >
            Kraken
          </h1>
          <p className="mt-1 text-sm" style={{ color: 'var(--ctp-subtext0)' }}>
            Command &amp; Control
          </p>
        </div>

        {/* Form */}
        <form onSubmit={handleSubmit} className="space-y-5">
          <div>
            <label
              htmlFor="token"
              className="mb-1 block text-sm font-medium"
              style={{ color: 'var(--ctp-subtext0)' }}
            >
              Operator Token
            </label>
            <input
              id="token"
              type="password"
              autoComplete="current-password"
              value={token}
              onChange={(e) => {
                setToken(e.target.value);
                setError('');
              }}
              placeholder="Enter your token"
              className="w-full rounded-lg px-4 py-2.5 text-sm outline-none transition-colors focus:ring-2"
              style={{
                backgroundColor: 'var(--ctp-surface0)',
                color: 'var(--ctp-text)',
                border: error ? '1px solid var(--ctp-red)' : '1px solid var(--ctp-surface1)',
                // @ts-expect-error CSS custom property
                '--tw-ring-color': 'var(--ctp-mauve)',
              }}
            />
            {error && (
              <p className="mt-1.5 text-xs" style={{ color: 'var(--ctp-red)' }}>
                {error}
              </p>
            )}
          </div>

          <button
            type="submit"
            className="w-full rounded-lg py-2.5 text-sm font-semibold transition-opacity hover:opacity-90 active:opacity-75"
            style={{
              backgroundColor: 'var(--ctp-mauve)',
              color: 'var(--ctp-base)',
            }}
          >
            Connect
          </button>
        </form>
      </div>
    </div>
  );
}
