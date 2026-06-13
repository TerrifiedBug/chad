import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, fireEvent } from '@testing-library/react';

const navigateMock = vi.fn();
vi.mock('react-router-dom', () => ({ useNavigate: () => navigateMock }));
vi.mock('@/hooks/use-auth', () => ({ useAuth: () => ({ hasPermission: () => true }) }));

import { CommandPalette } from '@/components/CommandPalette';

function pressCmdK() {
  fireEvent.keyDown(window, { key: 'k', metaKey: true });
}

describe('CommandPalette', () => {
  beforeEach(() => navigateMock.mockClear());

  it('is closed until ⌘K, then lists navigation commands', () => {
    render(<CommandPalette />);
    expect(screen.queryByLabelText('Command palette search')).toBeNull();

    pressCmdK();

    expect(screen.getByLabelText('Command palette search')).toBeInTheDocument();
    expect(screen.getByText('Dashboard')).toBeInTheDocument();
    expect(screen.getByText('Alerts')).toBeInTheDocument();
  });

  it('filters by query and navigates on Enter', () => {
    render(<CommandPalette />);
    pressCmdK();

    const input = screen.getByLabelText('Command palette search');
    fireEvent.change(input, { target: { value: 'alert' } });
    fireEvent.keyDown(input, { key: 'Enter' });

    expect(navigateMock).toHaveBeenCalledWith('/alerts');
  });
});
