import React, { createContext, useContext, useState, useEffect, useCallback } from 'react';
import type { User } from './types';
import { getMe } from './api';

interface AuthContextValue {
  user: User | null;
  token: string | null;
  isLoading: boolean;
  login: (token: string) => Promise<void>;
  logout: () => void;
}

const AuthContext = createContext<AuthContextValue | null>(null);

export function AuthProvider({ children }: { children: React.ReactNode }) {
  const [user, setUser] = useState<User | null>(null);
  const [token, setToken] = useState<string | null>(() => localStorage.getItem('warden_token'));
  const [isLoading, setIsLoading] = useState(true);

  const logout = useCallback(() => {
    localStorage.removeItem('warden_token');
    localStorage.removeItem('warden_user');
    setToken(null);
    setUser(null);
  }, []);

  const loginWithToken = useCallback(async (t: string) => {
    localStorage.setItem('warden_token', t);
    setToken(t);
    const me = await getMe();
    setUser(me);
    localStorage.setItem('warden_user', JSON.stringify(me));
  }, []);

  useEffect(() => {
    const storedToken = localStorage.getItem('warden_token');
    if (!storedToken) {
      setIsLoading(false);
      return;
    }
    const storedUser = localStorage.getItem('warden_user');
    if (storedUser) {
      try {
        setUser(JSON.parse(storedUser) as User);
      } catch {
        // ignore
      }
    }
    getMe()
      .then((me) => {
        setUser(me);
        localStorage.setItem('warden_user', JSON.stringify(me));
      })
      .catch(() => {
        logout();
      })
      .finally(() => setIsLoading(false));
  }, [logout]);

  return (
    <AuthContext.Provider value={{ user, token, isLoading, login: loginWithToken, logout }}>
      {children}
    </AuthContext.Provider>
  );
}

export function useAuth(): AuthContextValue {
  const ctx = useContext(AuthContext);
  if (!ctx) throw new Error('useAuth must be used within AuthProvider');
  return ctx;
}
