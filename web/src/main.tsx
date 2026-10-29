import { StrictMode, useEffect, useState } from "react";
import { createRoot } from "react-dom/client";
import { createBrowserRouter, RouterProvider } from "react-router";
import { QueryCache, QueryClient, QueryClientProvider } from "@tanstack/react-query";
import "./index.css";
import { ApiError, logout, resume } from "./lib/api";
import { Layout } from "./components/Layout";
import { Home } from "./pages/Home";
import { Login } from "./pages/Login";
import { Apply } from "./pages/Apply";
import { Bukti } from "./pages/Evidence";
import { Plan } from "./pages/Plan";
import { Planned } from "./pages/Planned";
import { Scan } from "./pages/Scan";

function App() {
  const [auth, setAuth] = useState<"checking" | "in" | "out">("checking");
  const [client] = useState(
    () =>
      new QueryClient({
        queryCache: new QueryCache({
          onError: (e) => {
            if (e instanceof ApiError && e.status === 401) setAuth("out");
          },
        }),
        defaultOptions: { queries: { retry: (n, e) => !(e instanceof ApiError && e.status === 401) && n < 2 } },
      }),
  );
  useEffect(() => {
    resume().then((ok) => setAuth(ok ? "in" : "out"));
  }, []);

  const [router] = useState(() =>
    createBrowserRouter([
      {
        path: "/",
        element: (
          <Layout
            onLogout={async () => {
              await logout();
              client.clear();
              setAuth("out");
            }}
          />
        ),
        children: [
          { index: true, element: <Home /> },
          { path: "scan", element: <Scan /> },
          { path: "rencana", element: <Plan /> },
          { path: "terapkan", element: <Apply /> },
          { path: "bukti", element: <Bukti /> },
          {
            path: "kinerja",
            element: (
              <Planned title="Kinerja" phase="S5 + U4" items={[
                "p50/p95, throughput, error, CPU/RAM, ukuran data",
                "Backup/restore sebelum vs sesudah pada 100 ribu dan 1 juta baris",
              ]} />
            ),
          },
          {
            path: "kunci-audit",
            element: (
              <Planned title="Kunci & Audit" phase="U5" items={[
                "Status KMS tanpa materi kunci",
                "Log akses dan dekripsi PII, alarm pembacaan massal",
              ]} />
            ),
          },
          {
            path: "patch",
            element: (
              <Planned title="Patch" phase="U5" cli="shield patch -t a|b --app-src <dir>" items={["Diff perbaikan kode berlabel needs human review"]} />
            ),
          },
          { path: "*", element: <Planned title="Tidak ditemukan" phase="–" items={["Halaman ini tidak ada."]} /> },
        ],
      },
    ]),
  );

  if (auth === "checking") return null;
  if (auth === "out") return <Login onDone={() => setAuth("in")} />;
  return (
    <QueryClientProvider client={client}>
      <RouterProvider router={router} />
    </QueryClientProvider>
  );
}

createRoot(document.getElementById("root")!).render(
  <StrictMode>
    <App />
  </StrictMode>,
);
