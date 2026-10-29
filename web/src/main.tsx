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
import { KeysAudit } from "./pages/KeysAudit";
import { Patch } from "./pages/Patch";
import { Performance } from "./pages/Performance";
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
          { path: "kinerja", element: <Performance /> },
          { path: "kunci-audit", element: <KeysAudit /> },
          { path: "patch", element: <Patch /> },
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
