import Navbar from '@/components/Navbar';
import Hero from '@/components/Hero';
import Pathways from '@/components/Pathways';
import NetworkStrip from '@/components/NetworkStrip';
import SystemMap from '@/components/SystemMap';
import ProtocolOverview from '@/components/ProtocolOverview';
import Ecosystem from '@/components/Ecosystem';
import GetStarted from '@/components/GetStarted';
import Footer from '@/components/Footer';
import { SectionHeader } from '@/components/ui/primitives';

export default function Home() {
  return (
    <main className="relative">
      <Navbar />
      <Hero />
      <Pathways />
      <NetworkStrip />

      <section className="border-t border-[var(--border)] bg-surface/30">
        <div className="mx-auto max-w-6xl px-6 py-24 lg:px-8">
          <SectionHeader
            kicker="The system"
            title="One settlement layer for storage and compute"
            intro="SUM Chain verifies and records the work done off-chain: inference nodes compute against model shards held in archive/SNIP storage, and the chain settles the proof. Follow the path a request takes."
          />
          <div className="mt-12">
            <SystemMap />
          </div>
        </div>
      </section>

      <ProtocolOverview />
      <Ecosystem />
      <GetStarted />
      <Footer />
    </main>
  );
}
