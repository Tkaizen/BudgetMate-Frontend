import React, { useState } from 'react';
import { View, Text, TextInput, TouchableOpacity, Image, ScrollView, Alert, KeyboardAvoidingView, Platform } from 'react-native';
import { SafeAreaView } from 'react-native-safe-area-context';
import { StatusBar } from 'expo-status-bar';
import { MaterialIcons } from '@expo/vector-icons';
import { useRouter } from 'expo-router';
import AsyncStorage from '@react-native-async-storage/async-storage';
import { moderateScale } from '../../src/utils/responsive';
import { styles, COLORS } from '../../styles/BudgetOnboarding.styles';
import { api } from '../../src/api/api';

// List of spending categories
const SPENDING_CATEGORIES = [
  'Housing',
  'Food',
  'Transportation',
  'Utilities',
  'Entertainment',
  'Healthcare',
  'Shopping',
  'Subscription',
];

export default function BudgetOnboarding() {
  const router = useRouter();

  // Track which step we're on (1, 2, 3, or 4)
  const [step, setStep] = useState(1);

  // Store all the form data
  const [income, setIncome] = useState('');
  const [frequency, setFrequency] = useState('');
  const [categories, setCategories] = useState([]);
  const [savingsRate, setSavingsRate] = useState('');
  const [emergencyGoal, setEmergencyGoal] = useState('');
  const [annualGoal, setAnnualGoal] = useState('');
  const [loading, setLoading] = useState(false);

  // Go to next step
  function nextStep() {
    // Validate step 2
    if (step === 2) {
      if (!income || parseFloat(income) <= 0) {
        Alert.alert('Required Field', 'Please enter your monthly income');
        return;
      }
      if (!frequency) {
        Alert.alert('Required Field', 'Please select how often you get paid');
        return;
      }
    }

    if (step < 4) {
      setStep(step + 1);
    }
  }

  // Go to previous step
  function previousStep() {
    if (step > 1) {
      setStep(step - 1);
    }
  }

  // Toggle category selection
  function toggleCategory(category) {
    if (categories.includes(category)) {
      setCategories(categories.filter(c => c !== category));
    } else {
      setCategories([...categories, category]);
    }
  }

  // Calculate savings estimate
  function calculateSavings() {
    const incomeValue = parseFloat(income);
    const rateValue = parseFloat(savingsRate);

    if (incomeValue && rateValue && incomeValue > 0 && rateValue > 0) {
      const estimate = (incomeValue * rateValue) / 100;
      return `Estimated monthly savings: ₱${estimate.toLocaleString()}`;
    }
    return 'Enter a percentage to see estimated savings';
  }

  // Finish Onboarding
  async function finishOnboarding() {
    setLoading(true);
    const budgetData = {
      monthlyIncome: parseFloat(income),
      paymentFrequency: frequency,
      spendingCategories: categories,
      targetSavingsRate: parseFloat(savingsRate) || 0,
      emergencyFundGoal: parseFloat(emergencyGoal) || 0,
      annualSavingsGoal: parseFloat(annualGoal) || 0,
    };

    try {
      // 1. Save locally
      await AsyncStorage.setItem('userBudget', JSON.stringify(budgetData));

      // 2. Save to backend
      try {
        await api.put('/api/budget', budgetData);
        console.log('Budget data synced to backend');
      } catch (apiError) {
        console.error('Failed to sync budget to backend:', apiError);
        // We don't block navigation if backend fails, but we log it
      }

      router.replace('/(tabs)/home');
    } catch (error) {
      console.error('Error saving budget data:', error);
      Alert.alert('Error', 'Failed to save budget data');
    } finally {
      setLoading(false);
    }
  }

  // Render Radio Button
  function RadioButton({ label }) {
    const isSelected = frequency === label;
    return (
      <TouchableOpacity
        style={[styles.radioButton, isSelected && styles.radioButtonSelected]}
        onPress={() => setFrequency(label)}
      >
        <View style={styles.radioCircle}>
          {isSelected && <View style={styles.radioCircleInner} />}
        </View>
        <Text style={[styles.radioText, isSelected && styles.radioTextSelected]}>
          {label}
        </Text>
      </TouchableOpacity>
    );
  }

  // Render Category Button
  function CategoryButton({ label }) {
    const isSelected = categories.includes(label);

    return (
      <TouchableOpacity
        style={[styles.categoryButton, isSelected && styles.categoryButtonSelected]}
        onPress={() => toggleCategory(label)}
      >
        <View style={[styles.checkbox, isSelected && styles.checkboxSelected]}>
          {isSelected && (
            <MaterialIcons name="check" size={moderateScale(16)} color={COLORS.text} />
          )}
        </View>
        <Text style={[styles.categoryText, isSelected && styles.categoryTextSelected]}>
          {label}
        </Text>
      </TouchableOpacity>
    );
  }

  // Render Navigation Buttons
  function NavigationButtons() {
    return (
      <View style={styles.navigationButtons}>
        <TouchableOpacity style={styles.backButton} onPress={previousStep}>
          <Text style={styles.backButtonText}>Back</Text>
        </TouchableOpacity>
        {step === 4 ? (
          <TouchableOpacity
            style={[styles.doneButton, loading && { opacity: 0.7 }]}
            onPress={finishOnboarding}
            disabled={loading}
          >
            <Text style={styles.nextButtonText}>{loading ? 'Saving...' : 'Done'}</Text>
          </TouchableOpacity>
        ) : (
          <TouchableOpacity style={styles.nextButton} onPress={nextStep}>
            <Text style={styles.nextButtonText}>Next</Text>
          </TouchableOpacity>
        )}
      </View>
    );
  }

  // STEP 1: Welcome Screen
  if (step === 1) {
    return (
      <SafeAreaView style={styles.container}>
        <StatusBar style="light" />
        <View style={styles.stepContainer}>
          <View style={styles.welcomeContent}>
            <Text style={styles.welcomeText}>Welcome to</Text>
            <Image
              source={require('../../assets/images/Logo.png')}
              style={styles.logo}
              resizeMode="contain"
            />
          </View>

          <TouchableOpacity style={styles.getStartedButton} onPress={nextStep}>
            <Text style={styles.getStartedButtonText}>Get Started</Text>
            <MaterialIcons name="arrow-forward" size={moderateScale(20)} color={COLORS.text} />
          </TouchableOpacity>
        </View>
      </SafeAreaView>
    );
  }

  // STEP 2: Monthly Income
  if (step === 2) {
    return (
      <SafeAreaView style={styles.container}>
        <StatusBar style="light" />
        <KeyboardAvoidingView
          behavior={Platform.OS === 'ios' ? 'padding' : 'height'}
          style={{ flex: 1 }}
        >
          <View style={styles.stepContainer}>
            <ScrollView showsVerticalScrollIndicator={false}>
              <Text style={styles.heading}>How much is your Monthly Income?</Text>
              <Text style={styles.subtitle}>This helps us create a personalized budget for you</Text>

              <Text style={styles.label}>Monthly Income</Text>
              <View style={styles.inputContainer}>
                <Text style={styles.currencyPrefix}>₱</Text>
                <TextInput
                  style={styles.input}
                  placeholder="20000"
                  placeholderTextColor="#8B86B8"
                  keyboardType="numeric"
                  value={income}
                  onChangeText={setIncome}
                />
              </View>

              <Text style={styles.subheading}>How often do you get paid?</Text>

              <RadioButton label="Weekly" />
              <RadioButton label="Bi-weekly" />
              <RadioButton label="Monthly" />
            </ScrollView>

            <NavigationButtons />
          </View>
        </KeyboardAvoidingView>
      </SafeAreaView>
    );
  }

  // STEP 3: Spending Categories
  if (step === 3) {
    return (
      <SafeAreaView style={styles.container}>
        <StatusBar style="light" />
        <KeyboardAvoidingView
          behavior={Platform.OS === 'ios' ? 'padding' : 'height'}
          style={{ flex: 1 }}
        >
          <View style={styles.stepContainer}>
            <ScrollView showsVerticalScrollIndicator={false}>
              <MaterialIcons name="pie-chart" size={moderateScale(40)} color={COLORS.accentGold} />

              <Text style={styles.heading}>What do you Spend on?</Text>
              <Text style={styles.subtitle}>Select your primary spending categories</Text>
              <Text style={styles.label}>Spending Categories</Text>

              <View style={styles.categoriesGrid}>
                {SPENDING_CATEGORIES.map((category) => (
                  <CategoryButton key={category} label={category} />
                ))}
              </View>

              <Text style={styles.label}>Target Savings Rate (% of Income)</Text>
              <View style={styles.inputContainer}>
                <TextInput
                  style={styles.input}
                  placeholder="10"
                  placeholderTextColor="#8B86B8"
                  keyboardType="numeric"
                  value={savingsRate}
                  onChangeText={setSavingsRate}
                />
                <Text style={styles.percentSign}>%</Text>
              </View>

              <Text style={styles.helperText}>{calculateSavings()}</Text>
            </ScrollView>

            <NavigationButtons />
          </View>
        </KeyboardAvoidingView>
      </SafeAreaView>
    );
  }

  // STEP 4: Financial Goals
  return (
    <SafeAreaView style={styles.container}>
      <StatusBar style="light" />
      <KeyboardAvoidingView
        behavior={Platform.OS === 'ios' ? 'padding' : 'height'}
        style={{ flex: 1 }}
      >
        <View style={styles.stepContainer}>
          <ScrollView showsVerticalScrollIndicator={false}>
            <MaterialIcons name="track-changes" size={moderateScale(40)} color={COLORS.accentGold} />

            <Text style={styles.heading}>Set your Financial Goals</Text>
            <Text style={styles.subtitle}>What are you saving for?</Text>

            <Text style={styles.label}>Emergency Fund Goal</Text>
            <View style={styles.inputContainer}>
              <Text style={styles.currencyPrefix}>₱</Text>
              <TextInput
                style={styles.input}
                placeholder="10000"
                placeholderTextColor="#8B86B8"
                keyboardType="numeric"
                value={emergencyGoal}
                onChangeText={setEmergencyGoal}
              />
            </View>
            <Text style={styles.helperText}>A safety net for unexpected costs. Aim for 3-6 months of essential expenses.</Text>

            <Text style={styles.label}>Annual Savings Goal</Text>
            <View style={styles.inputContainer}>
              <Text style={styles.currencyPrefix}>₱</Text>
              <TextInput
                style={styles.input}
                placeholder="15000"
                placeholderTextColor="#8B86B8"
                keyboardType="numeric"
                value={annualGoal}
                onChangeText={setAnnualGoal}
              />
            </View>
            <Text style={styles.helperText}>The total amount you want to save by the end of the year for vacations, gifts, or big purchases.</Text>
          </ScrollView>

          <NavigationButtons />
        </View>
      </KeyboardAvoidingView>
    </SafeAreaView>
  );
}