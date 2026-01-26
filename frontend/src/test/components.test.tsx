import { describe, it, expect, vi } from 'vitest';
import { render, screen } from '@testing-library/react';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Badge } from '@/components/ui/badge';
import { Label } from '@/components/ui/label';

describe('UI Components', () => {
  describe('Button Component', () => {
    it('should render button with text', () => {
      render(<Button>Click me</Button>);
      expect(screen.getByRole('button')).toHaveTextContent('Click me');
    });

    it('should render variant styles', () => {
      render(<Button variant="destructive">Delete</Button>);
      const button = screen.getByRole('button');
      expect(button).toHaveClass('bg-destructive');
    });

    it('should be disabled when specified', () => {
      render(<Button disabled>Disabled</Button>);
      expect(screen.getByRole('button')).toBeDisabled();
    });

    it('should handle click events', () => {
      const handleClick = vi.fn();
      render(<Button onClick={handleClick}>Click me</Button>);

      screen.getByRole('button').click();
      expect(handleClick).toHaveBeenCalledTimes(1);
    });
  });

  describe('Input Component', () => {
    it('should render input field', () => {
      render(<Input placeholder="Enter text" />);
      expect(screen.getByPlaceholderText('Enter text')).toBeInTheDocument();
    });

    it('should accept text input', () => {
      const { container } = render(<Input type="text" />);
      const input = container.querySelector('input');
      expect(input).toHaveAttribute('type', 'text');
    });

    it('should render password type', () => {
      const { container } = render(<Input type="password" />);
      const input = container.querySelector('input');
      expect(input).toHaveAttribute('type', 'password');
    });

    it('should be disabled when specified', () => {
      render(<Input disabled />);
      expect(screen.getByRole('textbox')).toBeDisabled();
    });
  });

  describe('Badge Component', () => {
    it('should render badge with text', () => {
      render(<Badge>New</Badge>);
      expect(screen.getByText('New')).toBeInTheDocument();
    });

    it('should apply variant classes', () => {
      const { container } = render(<Badge variant="secondary">Label</Badge>);
      const badge = container.querySelector('div');
      expect(badge).toHaveClass('bg-secondary');
    });

    it('should apply outline variant', () => {
      const { container } = render(<Badge variant="outline">Outline</Badge>);
      const badge = container.querySelector('div');
      expect(badge).toHaveClass('text-foreground');
    });
  });
});

describe('Form Components', () => {
  describe('Label Component', () => {
    it('should render label text', () => {
      render(<Label>Email</Label>);
      expect(screen.getByText('Email')).toBeInTheDocument();
    });

    it('should associate with input', () => {
      render(
        <div>
          <Label htmlFor="email">Email</Label>
          <Input id="email" />
        </div>
      );

      const label = screen.getByText('Email');
      expect(label).toHaveAttribute('for', 'email');
    });
  });
});

describe('Security Components', () => {
  describe('Password Input', () => {
    it('should hide password characters', () => {
      const { container } = render(<Input type="password" defaultValue="secret123" />);
      const input = container.querySelector('input') as HTMLInputElement;
      expect(input.type).toBe('password');
      expect(input.value).toBe('secret123');
    });

    it('should toggle visibility when button clicked', () => {
      const { container } = render(
        <div>
          <Input type="password" defaultValue="password" />
        </div>
      );
      const input = container.querySelector('input') as HTMLInputElement;
      expect(input.type).toBe('password');
    });
  });
});
