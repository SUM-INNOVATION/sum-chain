import { Routes, Route } from 'react-router-dom';
import Layout from './components/Layout';
import Home from './pages/Home';
import BlockDetails from './pages/BlockDetails';
import TransactionDetails from './pages/TransactionDetails';
import AddressDetails from './pages/AddressDetails';
import Validators from './pages/Validators';

function App() {
  return (
    <Layout>
      <Routes>
        <Route path="/" element={<Home />} />
        <Route path="/block/:height" element={<BlockDetails />} />
        <Route path="/tx/:hash" element={<TransactionDetails />} />
        <Route path="/address/:address" element={<AddressDetails />} />
        <Route path="/validators" element={<Validators />} />
      </Routes>
    </Layout>
  );
}

export default App;
