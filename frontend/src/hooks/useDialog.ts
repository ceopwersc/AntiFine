import { useEffect,useRef } from 'react';

const dialogStack: HTMLElement[] = [];

export function useDialog<T extends HTMLElement = HTMLDivElement>(onClose: () => void) {
  const close = useRef(onClose);
  const dialogRef = useRef<T>(null);
  useEffect(() => { close.current = onClose; }, [onClose]);
  useEffect(() => {
    const previous = document.activeElement as HTMLElement | null;
    const dialog = dialogRef.current;
    if (!dialog) return;
    dialogStack.push(dialog);
    const controls = () => Array.from(dialog?.querySelectorAll<HTMLElement>('button:not(:disabled), input:not(:disabled), select:not(:disabled), textarea:not(:disabled), [tabindex="0"]') ?? []).filter(e => e.getClientRects().length);
    (controls()[0] ?? dialog)?.focus();
    const handle = (event: KeyboardEvent) => {
      // Only the active dialog owns focus while a prior drawer animates out.
      if (dialogStack[dialogStack.length - 1] !== dialog) return;
      if (event.key === 'Escape') { event.preventDefault(); close.current(); }
      if (event.key === 'Tab') {
        const items = controls();
        if (!items.length) { event.preventDefault(); dialog?.focus(); return; }
        const first = items[0], last = items[items.length - 1];
        if (event.shiftKey && (document.activeElement === first || !dialog?.contains(document.activeElement))) { event.preventDefault(); last.focus(); }
        else if (!event.shiftKey && (document.activeElement === last || !dialog?.contains(document.activeElement))) { event.preventDefault(); first.focus(); }
      }
    };
    document.addEventListener('keydown', handle);
    return () => {
      document.removeEventListener('keydown', handle);
      const position = dialogStack.indexOf(dialog);
      const wasActive = position === dialogStack.length - 1;
      if (position >= 0) dialogStack.splice(position, 1);
      if (wasActive && previous?.isConnected) previous.focus();
    };
  }, []);
  return dialogRef;
}
