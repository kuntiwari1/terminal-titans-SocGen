import React from 'react';
import { Box, Button } from '@mui/material';
import { useNavigate, useLocation } from 'react-router-dom';

const CURRENT_TIMESTAMP = '2025-07-12 19:54:41'
const CURRENT_USER = 'Prateek-glitch'

export default function Navigation() {
  const navigate = useNavigate();
  const location = useLocation();

  const isActive = (path) => location.pathname === path;

  return (
    <Box sx={{ display: 'flex', justifyContent: 'flex-end', gap: 1 }}>
      <Button
        variant="text"
        onClick={() => navigate('/')}
        sx={{
          color: isActive('/') ? 'white' : '#666',
          backgroundColor: isActive('/') ? '#2a2a2a' : 'transparent',
          textTransform: 'none',
          '&:hover': {
            backgroundColor: isActive('/') ? '#2a2a2a' : 'rgba(255, 255, 255, 0.08)'
          }
        }}
      >
        Dashboard
      </Button>
      <Button
        variant="text"
        onClick={() => navigate('/history')}
        sx={{
          color: isActive('/history') ? 'white' : '#666',
          backgroundColor: isActive('/history') ? '#2a2a2a' : 'transparent',
          textTransform: 'none',
          '&:hover': {
            backgroundColor: isActive('/history') ? '#2a2a2a' : 'rgba(255, 255, 255, 0.08)'
          }
        }}
      >
        History
      </Button>
      <Button
        variant="text"
        onClick={() => navigate('/detailed-report')}
        sx={{
          color: isActive('/detailed-report') ? 'white' : '#666',
          backgroundColor: isActive('/detailed-report') ? '#2a2a2a' : 'transparent',
          textTransform: 'none',
          '&:hover': {
            backgroundColor: isActive('/detailed-report') ? '#2a2a2a' : 'rgba(255, 255, 255, 0.08)'
          }
        }}
      >
        Detailed Report
      </Button>
    </Box>
  );
}