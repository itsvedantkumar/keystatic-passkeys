export default function KeystaticLayout({ children }: { children: React.ReactNode }) {
  return (
    <>
      <style>{`
        :focus-visible { outline: 3px solid #005fcc !important; outline-offset: 2px !important; }
        @media (prefers-reduced-motion: reduce) {
          *, *::before, *::after { animation-duration: 0.01ms !important; transition-duration: 0.01ms !important; }
        }
        @media (forced-colors: active) {
          button, [role="button"] { forced-color-adjust: none; }
        }
      `}</style>
      {children}
    </>
  );
}
