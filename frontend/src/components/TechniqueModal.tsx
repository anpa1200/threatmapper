/**
 * Portal-based modal wrapper around TechniquePanel.
 * Renders as a slide-in right panel with a dimmed backdrop.
 * Close with backdrop click or Escape key.
 */

import { useEffect } from 'react';
import { createPortal } from 'react-dom';
import { TechniquePanel } from './Navigator/TechniquePanel';

interface Props {
  attackId: string | null;
  onClose: () => void;
}

export function TechniqueModal({ attackId, onClose }: Props) {
  useEffect(() => {
    if (!attackId) return;
    const handler = (e: KeyboardEvent) => { if (e.key === 'Escape') onClose(); };
    window.addEventListener('keydown', handler);
    return () => window.removeEventListener('keydown', handler);
  }, [attackId, onClose]);

  if (!attackId) return null;

  return createPortal(
    <div className="fixed inset-0 z-50 flex justify-end">
      <div
        className="absolute inset-0 bg-black/60 backdrop-blur-[1px]"
        onClick={onClose}
      />
      <div className="relative z-10 h-full flex flex-col shadow-2xl">
        <TechniquePanel attackId={attackId} onClose={onClose} />
      </div>
    </div>,
    document.body
  );
}
