// ===== Root Layout =====
// This is the main entry point of the app (like App.js/ts).
// It handles:
// 1. Loading custom fonts (Poppins)
// 2. Showing/Hiding the Splash Screen
// 3. Defining the main navigation container (Stack)

import { Stack } from "expo-router";
import { useFonts } from 'expo-font';
import { Poppins_400Regular, Poppins_500Medium, Poppins_600SemiBold, Poppins_700Bold } from '@expo-google-fonts/poppins';
import * as SplashScreen from 'expo-splash-screen';
import { useEffect } from 'react';
import AsyncStorage from '@react-native-async-storage/async-storage';

// Keep the splash screen visible while we load resources
SplashScreen.preventAutoHideAsync();

export default function RootLayout() {
  // Load the fonts from the assets/modules
  const [fontsLoaded] = useFonts({
    'Poppins-Regular': Poppins_400Regular,
    'Poppins-Medium': Poppins_500Medium,
    'Poppins-SemiBold': Poppins_600SemiBold,
    'Poppins-Bold': Poppins_700Bold,
  });

  // Hide the splash screen once fonts are ready and load user data
  useEffect(() => {
    const initializeApp = async () => {
      if (fontsLoaded) {
        // Load stored user data and token
        try {
          const storedUserData = await AsyncStorage.getItem('userData');
          const storedToken = await AsyncStorage.getItem('authToken');

          if (storedUserData) {
            global.userData = JSON.parse(storedUserData);
          }
          if (storedToken) {
            global.authToken = storedToken;
          }
        } catch (error) {
          console.error('Error loading stored data:', error);
        }

        SplashScreen.hideAsync();
      }
    };

    initializeApp();
  }, [fontsLoaded]);

  // Don't render anything until fonts are loaded (prevents glitches)
  if (!fontsLoaded) {
    return null;
  }

  // Render the Stack Navigator (the container for all screens)
  // headerShown: false means we hide the default top bar
  return <Stack screenOptions={{ headerShown: false }} />;
}
