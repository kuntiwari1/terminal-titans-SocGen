import React from 'react';
import { BrowserRouter as Router, Routes, Route } from 'react-router-dom';
import { ThemeProvider, CssBaseline, Box, Typography } from '@mui/material';
import { theme } from './theme/theme';
import Navigation from './components/Navigation';
import Dashboard from './components/Dashboard';
import History from './components/History';
import DetailedReport from './components/DetailedReport';

// Current settings
const CURRENT_USER = 'Prateek-glitch';
const CURRENT_TIMESTAMP = '2025-07-12 19:50:15';

function App() {
  return (
    <Router>
      <Box sx={{ 
        bgcolor: '#212121', 
        minHeight: '100vh', 
        color: 'white',
        p: 3 
      }}>
        <Box sx={{ mb: 4 }}>
          <Typography variant="h4" component="h1" sx={{ mb: 2 }}>
            ⭐ PentestApp
          </Typography>
          <Navigation />
        </Box>

        <Routes>
          <Route path="/" element={<Dashboard />} />
          <Route path="/history" element={<History />} />
          <Route path="/detailed-report/:scanId" element={<DetailedReport />} />
          <Route path="/detailed-report" element={<DetailedReport />} />
        </Routes>
      </Box>
    </Router>
  );
}

export default App;