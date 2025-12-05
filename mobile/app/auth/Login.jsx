import { View, Text, StyleSheet, TextInput, TouchableOpacity, Image } from 'react-native';
import React, { useState } from 'react';
import { StatusBar } from 'expo-status-bar';
import { LinearGradient } from 'expo-linear-gradient';
import { MaterialIcons } from '@expo/vector-icons';
import { Link, useRouter } from "expo-router";
import { api } from "../../src/api/api";
import AsyncStorage from '@react-native-async-storage/async-storage';

const Login = () => {
  const [username, setUsername] = useState('');   // this is actually email
  const [password, setPassword] = useState('');
  const [errors, setErrors] = useState({});
  const [showPassword, setShowPassword] = useState(false);
  const [rememberMe, setRememberMe] = useState(false);
  const [loading, setLoading] = useState(false);

  const router = useRouter();

  const handleLogin = async () => {
    setErrors({});
    let currentErrors = {};

    if (!username) currentErrors.username = "Email or Username is required";
    if (!password) currentErrors.password = "Password is required";

    if (Object.keys(currentErrors).length > 0) {
      setErrors(currentErrors);
      return;
    }

    setLoading(true);
    try {
      const response = await api.post("/api/auth/login", {
        email: username,
        password: password,
      });

      const { token, user } = response.data;

      // Store token (basic approach)
      global.authToken = token;

      // Save user data to AsyncStorage
      await AsyncStorage.setItem('userData', JSON.stringify({
        username: user.username || user.name,
        email: user.email,
        name: user.name || user.username,
        id: user.id
      }));

      console.log("Logged in user:", user);
      console.log("Remember Me:", rememberMe);
      console.log("Saved to AsyncStorage:", user.name || user.username);

      router.replace("/(tabs)/home");
    } catch (error) {
      console.log("Login error:", error?.response?.data || error.message);
      const message = error?.response?.data?.message || "Login failed";
      alert(message);
    } finally {
      setLoading(false);
    }
  };

  return (
    <View style={styles.container}>
      <StatusBar style="light" />

      <View style={styles.upper}>
        <Text style={styles.big}>Sign in to your{'\n'}Account</Text>
        <Text style={styles.small}>Enter your email/username and password to login</Text>
      </View>

      <View style={styles.lower}>
        <LinearGradient
          colors={['#E3823C', '#47447D']}
          locations={[0.1, 0.95]}
          style={StyleSheet.absoluteFill}
        />
      </View>

      {/* Login Box */}
      <View style={styles.box}>
        <TouchableOpacity style={styles.google}>
          <View style={{ flexDirection: 'row', alignItems: 'center' }}>
            <Image
              source={require('../../assets/images/googlelogo.png')}
              style={{ width: 25, height: 25 }}
            />
            <Text style={styles.googleText}>Continue with Google</Text>
          </View>
        </TouchableOpacity>

        <View style={styles.orContainer}>
          <View style={styles.orLine} />
          <Text style={styles.orText}>Or login with</Text>
        </View>

        <Text style={styles.label}>Email or Username</Text>
        <TextInput
          placeholder="Username or Email"
          keyboardType="email-address"
          style={[styles.input, errors.username && styles.inputError]}
          onChangeText={(text) => {
            setUsername(text);
            if (errors.username) setErrors({ ...errors, username: null });
          }}
          value={username}
        />
        {errors.username && <Text style={styles.errorText}>{errors.username}</Text>}

        <Text style={styles.label}>Password</Text>

        <View>
          <TextInput
            placeholder="Password"
            secureTextEntry={!showPassword}
            style={[styles.input, errors.password && styles.inputError]}
            onChangeText={(text) => {
              setPassword(text);
              if (errors.password) setErrors({ ...errors, password: null });
            }}
            value={password}
          />

          <TouchableOpacity
            onPress={() => setShowPassword(!showPassword)}
            style={styles.eyeIcon}
          >
            <MaterialIcons
              name={showPassword ? 'visibility' : 'visibility-off'}
              size={24}
              color="#555"
            />
          </TouchableOpacity>
        </View>
        {errors.password && <Text style={styles.errorText}>{errors.password}</Text>}

        <View style={styles.options}>
          <TouchableOpacity
            style={styles.checkboxRow}
            onPress={() => setRememberMe(!rememberMe)}
            activeOpacity={0.7}
          >
            <View style={[styles.checkbox, rememberMe && styles.checkedBox]}>
              {rememberMe && (
                <MaterialIcons name="check" size={16} color="#fff" />
              )}
            </View>

            <Text style={styles.rememberText}>Remember me</Text>
          </TouchableOpacity>

          <TouchableOpacity>
            <Text style={styles.forgot}>Forgot Password?</Text>
          </TouchableOpacity>
        </View>

        <TouchableOpacity
          style={[styles.button, loading && { opacity: 0.5 }]}
          onPress={handleLogin}
          disabled={loading}
        >
          <Text style={styles.buttonText}>
            {loading ? "Logging in..." : "Login"}
          </Text>
        </TouchableOpacity>

        <Text style={styles.signup}>
          Don't have an account?
          <Link style={styles.signUpLink} href="/auth/Signup"> Sign up</Link>
        </Text>
      </View>
    </View>
  );
};

const styles = StyleSheet.create({
  container: {
    flex: 1,
    backgroundColor: '#141326'
  },

  upper: {
    flex: 1,
    alignItems: 'center',
  },

  lower: {
    flex: 1,
  },

  box: {
    width: '90%',
    backgroundColor: '#ffffff',
    borderRadius: 30,
    padding: 20,
    position: 'absolute',
    top: 215,
    alignSelf: 'center',
  },

  big: {
    color: '#ffffff',
    fontSize: 32,
    fontWeight: '600',
    textAlign: 'center',
    position: 'absolute',
    top: 75,
  },

  small: {
    color: '#ffffff',
    fontSize: 12,
    fontWeight: '400',
    textAlign: 'center',
    position: 'absolute',
    top: 160,
  },

  google: {
    width: '100%',
    height: 50,
    borderWidth: 1,
    borderColor: '#969696',
    borderRadius: 10,
    justifyContent: 'center',
    alignItems: 'center',
    backgroundColor: '#fff',
    shadowColor: '#000',
    shadowOffset: { width: 2, height: 5 },
    shadowOpacity: 0.3,
    shadowRadius: 6,
    elevation: 10,
  },

  googleText: {
    marginLeft: 10,
    fontSize: 18,
    fontWeight: '500',
  },

  orContainer: {
    marginVertical: 14,
    alignItems: 'center',
    position: 'relative',
  },

  orLine: {
    position: 'absolute',
    top: '50%',
    left: 0,
    right: 0,
    height: 1,
    backgroundColor: '#ccc',
  },

  orText: {
    backgroundColor: '#fff',
    paddingHorizontal: 10,
    color: '#555',
    fontSize: 14,
    textAlign: 'center',
  },

  label: {
    marginBottom: 5,
    fontWeight: '500',
  },

  input: {
    borderWidth: 1,
    borderColor: '#969696',
    borderRadius: 8,
    padding: 10,
    paddingRight: 45,
    fontSize: 16,
    marginBottom: 10,
    backgroundColor: '#fff',
    shadowColor: '#000',
    shadowOffset: { width: 2, height: 5 },
    shadowOpacity: 0.3,
    shadowRadius: 6,
    elevation: 10,
  },

  eyeIcon: {
    position: 'absolute',
    right: 8,
    top: '10%',
    padding: 5,
  },

  options: {
    flexDirection: 'row',
    justifyContent: 'space-between',
    marginBottom: 20,
    alignItems: 'center',
  },

  checkboxRow: {
    flexDirection: 'row',
    alignItems: 'center',
  },

  checkbox: {
    width: 18,
    height: 18,
    borderWidth: 1.2,
    borderColor: '#000',
    borderRadius: 7,
    justifyContent: 'center',
    alignItems: 'center',
    marginRight: 8,
  },

  checkedBox: {
    backgroundColor: '#1300BC',
    borderColor: '#1300BC',
  },

  rememberText: {
    fontSize: 14,
  },

  forgot: {
    color: '#1300BC',
  },

  button: {
    backgroundColor: '#1300BC',
    padding: 15,
    borderRadius: 10,
    alignItems: 'center',
    marginBottom: 15,
    shadowColor: '#000',
    shadowOffset: { width: 2, height: 5 },
    shadowOpacity: 0.3,
    shadowRadius: 6,
    elevation: 10,
  },

  buttonText: {
    color: '#fff',
    fontWeight: '600',
    fontSize: 16,
  },

  signup: {
    textAlign: 'center',
    color: '#555',
  },

  signUpLink: {
    color: '#0000EE',
    fontWeight: '600',
  },

  inputError: {
    borderColor: 'red',
    borderWidth: 1,
  },

  errorText: {
    color: 'red',
    fontSize: 12,
    marginBottom: 10,
    marginTop: -5,
  },
});

export default Login;
