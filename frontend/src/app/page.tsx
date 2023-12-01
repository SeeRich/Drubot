import Image from "next/image";
import WebSocketComponent from "./components/Websocket";

export default function Home() {
  return (
    <main className="flex min-h-screen flex-col items-center justify-between p-24">
      <WebSocketComponent />
    </main>
  );
}
