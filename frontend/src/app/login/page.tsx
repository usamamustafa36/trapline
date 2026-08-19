/**
 * Console gate page.
 *
 * The form is a separate client component so `useSearchParams` sits under a Suspense
 * boundary, which static prerendering requires.
 */
import { Suspense } from "react";

import { LoginForm } from "./LoginForm";

export const metadata = { title: "Sign in", robots: { index: false, follow: false } };

export default function LoginPage() {
  return (
    <Suspense
      fallback={<main className="grid min-h-screen place-items-center bg-void" aria-busy="true" />}
    >
      <LoginForm />
    </Suspense>
  );
}
