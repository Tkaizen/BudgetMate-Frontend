import axios from "axios";
import { Platform } from "react-native";
import Constants from "expo-constants";

const {
  WEB_API_URL,
  IOS_API_URL,
  ANDROID_API_URL,
  DEFAULT_API_URL,
} = Constants.expoConfig.extra;

const baseURL = Platform.select({
  web: WEB_API_URL,
  ios: IOS_API_URL,
  android: ANDROID_API_URL,
  default: DEFAULT_API_URL,
});

console.log("API baseURL =", baseURL);

export const api = axios.create({
  baseURL,
});

api.interceptors.request.use((config) => {
  if (global.authToken) {
    config.headers.Authorization = `Bearer ${global.authToken}`;
  }
  return config;
});

api.interceptors.response.use(
  (response) => response,
  (error) => {
    if (error.response?.status === 400) {
      // Validation error from backend
      console.error("Validation Error:", error.response.data.message);
    }
    return Promise.reject(error);
  }
);