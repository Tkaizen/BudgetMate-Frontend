// ===== API Configuration =====
// This file sets up the connection to our backend server (API).
// It handles the URL configuration and automatically adds the user's token to requests.

import axios from "axios";
import { Platform } from "react-native";
import Constants from "expo-constants";

// Get backend URLs from app.config.js (environment variables)
const {
  WEB_API_URL,
  IOS_API_URL,
  ANDROID_API_URL,
  DEFAULT_API_URL,
} = Constants.expoConfig.extra;

// Select the correct URL based on the device we are running on
const baseURL = Platform.select({
  web: WEB_API_URL,      // Browser
  ios: IOS_API_URL,      // iPhone Simulator/Device
  android: ANDROID_API_URL, // Android Emulator/Device
  default: DEFAULT_API_URL,
});

console.log("API baseURL =", baseURL);

// Create the Axios instance (our HTTP client)
export const api = axios.create({
  baseURL,
});

// --- Interceptors ---
// These run automatically before every request or after every response.

// Request Interceptor: Adds the user's token to the request headers
// Request Interceptor: Adds the user's token to the request headers
api.interceptors.request.use((config) => {
  // If we have a token stored globally, attach it
  if (global.authToken) {
    config.headers.Authorization = `Bearer ${global.authToken}`;
  }
  return config;
});

// Response Interceptor: Handles global errors
api.interceptors.response.use(
  (response) => response, // Return successful responses as is
  (error) => {
    if (error.response?.status === 400) {
      // Log validation errors (like "Invalid password") from the backend
      console.error("Validation Error:", error.response.data.message);
    }
    return Promise.reject(error);
  }
);

// ===== Article API Functions =====

/**
 * Fetch all published articles
 * Public endpoint - no authentication required
 */
export const fetchArticles = async () => {
  const response = await api.get("/api/articles");
  return response.data;
};

/**
 * Create a new article (Admin only)
 * @param {Object} articleData - Article data (title, description, url, etc.)
 */
export const createArticle = async (articleData) => {
  const response = await api.post("/api/articles", articleData);
  return response.data;
};

/**
 * Update an existing article (Admin only)
 * @param {string} id - Article ID
 * @param {Object} articleData - Updated article data
 */
export const updateArticle = async (id, articleData) => {
  const response = await api.put(`/api/articles/${id}`, articleData);
  return response.data;
};

/**
 * Delete an article (Admin only)
 * @param {string} id - Article ID
 */
export const deleteArticle = async (id) => {
  const response = await api.delete(`/api/articles/${id}`);
  return response.data;
};

// ===== Admin API Functions =====

/**
 * Create a new admin user (Admin only)
 * @param {Object} userData - User data (name, email, password, confirmPassword)
 */
export const createAdminUser = async (userData) => {
  const response = await api.post("/api/auth/admin/create", userData);
  return response.data;
};

// ===== Job API Functions =====

/**
 * Fetch all published jobs
 * Public endpoint - no authentication required
 */
export const fetchJobs = async () => {
  const response = await api.get("/api/jobs");
  return response.data;
};

/**
 * Create a new job (Admin only)
 * @param {Object} jobData - Job data (title, description, payRange, etc.)
 */
export const createJob = async (jobData) => {
  const response = await api.post("/api/jobs", jobData);
  return response.data;
};

/**
 * Update an existing job (Admin only)
 * @param {string} id - Job ID
 * @param {Object} jobData - Updated job data
 */
export const updateJob = async (id, jobData) => {
  const response = await api.put(`/api/jobs/${id}`, jobData);
  return response.data;
};

/**
 * Delete a job (Admin only)
 * @param {string} id - Job ID
 */
export const deleteJob = async (id) => {
  const response = await api.delete(`/api/jobs/${id}`);
  return response.data;
};
