/** Generic server-style 404 — no product name, logo, or console chrome. */
export const metadata = {
  title: "Not Found",
  robots: { index: false, follow: false },
};

export default function NotFound() {
  return (
    <>
      <style>{`
        html, body {
          background: #ffffff !important;
          color: #000000 !important;
          margin: 0 !important;
          padding: 0 !important;
        }
        body::before, body::after {
          display: none !important;
          content: none !important;
        }
      `}</style>
      <div
        style={{
          fontFamily: "Times New Roman, Times, serif",
          background: "#ffffff",
          color: "#000000",
          minHeight: "100vh",
          margin: 0,
          padding: "1.5rem 1.25rem",
        }}
      >
        <h1
          style={{
            fontSize: "1.5rem",
            fontWeight: 700,
            margin: "0 0 0.5rem 0",
            padding: 0,
          }}
        >
          Not Found
        </h1>
        <p style={{ fontSize: "1rem", margin: 0, padding: 0 }}>
          The requested URL was not found on this server.
        </p>
      </div>
    </>
  );
}
