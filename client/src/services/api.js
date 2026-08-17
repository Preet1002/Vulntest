/**
 * Client for the scanner API.
 *
 * In development every call is same-origin: Vite proxies /api to the Node
 * backend (see vite.config.js), which keeps Server-Sent Events simple.
 */
import axios from 'axios';

export const API_BASE = import.meta.env.VITE_API_BASE || '/api';

const client = axios.create({
  baseURL: API_BASE,
  timeout: 20_000,
  headers: { 'Content-Type': 'application/json' },
});

/** Turn an axios failure into a plain Error carrying the API's message. */
function toError(error) {
  const payload = error?.response?.data?.error;
  const message =
    payload?.message ||
    (error?.code === 'ECONNABORTED'
      ? 'The scanner API did not respond in time.'
      : error?.message || 'The scanner API is unreachable.');
  const wrapped = new Error(message);
  wrapped.code = payload?.code || error?.code || 'request_failed';
  wrapped.status = error?.response?.status ?? null;
  return wrapped;
}

const request = async (promise) => {
  try {
    const response = await promise;
    return response.data;
  } catch (error) {
    throw toError(error);
  }
};

export const getHealth = () => request(client.get('/health'));

export const getScanConfig = () => request(client.get('/config'));

export const validateTarget = (target) => request(client.post('/validate-target', { target }));

/** `authorized` must be true - the API refuses the scan otherwise. */
export const startScan = ({ target, config, authorized }) =>
  request(client.post('/scans', { target, config, authorized }));

export const stopScan = (id) => request(client.post(`/scans/${id}/stop`));

export const getScan = (id) => request(client.get(`/scans/${id}`));

export const getScanStatus = (id) => request(client.get(`/scans/${id}/status`));

export const getFindings = (id, params = {}) => request(client.get(`/scans/${id}/findings`, { params }));

export const getEndpoints = (id, params = {}) => request(client.get(`/scans/${id}/endpoints`, { params }));

export const listScans = () => request(client.get('/scans'));

/** URL for the EventSource progress stream. */
export const eventStreamUrl = (id) => `${API_BASE}/scans/${id}/events`;
