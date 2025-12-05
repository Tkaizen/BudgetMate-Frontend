import React, { useState, useEffect } from 'react';
import { View, Text, TextInput, TouchableOpacity, StyleSheet, ScrollView, Alert, ActivityIndicator } from 'react-native';
import { SafeAreaView } from 'react-native-safe-area-context';
import { StatusBar } from 'expo-status-bar';
import { useRouter } from 'expo-router';
import { MaterialIcons } from '@expo/vector-icons';
import AsyncStorage from '@react-native-async-storage/async-storage';
import { scale, verticalScale, moderateScale } from '../../src/utils/responsive';
import { api } from '../../src/api/api';

const COLORS = {
    background: '#141326',
    cardBg: '#433DA3',
    primary: '#E3823C',
    accent: '#E33C3C',
    text: '#FFFFFF',
    textSecondary: '#D7C7EC',
    yellow: '#FFC107',
};

export default function EditBudget() {
    const router = useRouter();
    const [loading, setLoading] = useState(true);
    const [saving, setSaving] = useState(false);

    const [income, setIncome] = useState('');
    const [savingsRate, setSavingsRate] = useState('');
    const [emergencyGoal, setEmergencyGoal] = useState('');
    const [annualGoal, setAnnualGoal] = useState('');

    useEffect(() => {
        loadData();
    }, []);

    const loadData = async () => {
        try {
            const savedData = await AsyncStorage.getItem('userBudget');
            if (savedData != null) {
                const data = JSON.parse(savedData);
                setIncome(data.monthlyIncome?.toString() || '');
                setSavingsRate(data.targetSavingsRate?.toString() || '');
                setEmergencyGoal(data.emergencyFundGoal?.toString() || '');
                setAnnualGoal(data.annualSavingsGoal?.toString() || '');
            }
        } catch (error) {
            console.error('Failed to load budget data', error);
            Alert.alert('Error', 'Failed to load current settings');
        } finally {
            setLoading(false);
        }
    };

    const handleSave = async () => {
        if (!income || parseFloat(income) <= 0) {
            Alert.alert('Error', 'Please enter a valid monthly income');
            return;
        }

        setSaving(true);
        try {
            // Get existing data first to preserve other fields like categories/frequency
            const existingDataStr = await AsyncStorage.getItem('userBudget');
            const existingData = existingDataStr ? JSON.parse(existingDataStr) : {};

            const updatedData = {
                ...existingData,
                monthlyIncome: parseFloat(income),
                targetSavingsRate: parseFloat(savingsRate) || 0,
                emergencyFundGoal: parseFloat(emergencyGoal) || 0,
                annualSavingsGoal: parseFloat(annualGoal) || 0,
            };

            // 1. Save locally
            await AsyncStorage.setItem('userBudget', JSON.stringify(updatedData));

            // 2. Save to backend
            try {
                await api.put('/api/budget', updatedData);
            } catch (apiError) {
                console.error('Failed to sync budget to backend:', apiError);
                // Continue since local save worked
            }

            Alert.alert('Success', 'Budget settings updated!', [
                { text: 'OK', onPress: () => router.back() }
            ]);
        } catch (error) {
            console.error('Failed to save budget data', error);
            Alert.alert('Error', 'Failed to save changes');
        } finally {
            setSaving(false);
        }
    };

    if (loading) {
        return (
            <View style={[styles.container, styles.center]}>
                <ActivityIndicator size="large" color={COLORS.primary} />
            </View>
        );
    }

    return (
        <SafeAreaView style={styles.container} edges={['top', 'left', 'right']}>
            <StatusBar style="light" backgroundColor={COLORS.background} />

            {/* Header */}
            <View style={styles.header}>
                <TouchableOpacity onPress={() => router.back()} style={styles.backButton}>
                    <MaterialIcons name="arrow-back" size={moderateScale(24)} color={COLORS.text} />
                </TouchableOpacity>
                <Text style={styles.headerTitle}>Edit Budget</Text>
                <View style={{ width: moderateScale(24) }} />
            </View>

            <ScrollView style={styles.scrollView} contentContainerStyle={styles.content}>

                {/* Monthly Income */}
                <View style={styles.inputGroup}>
                    <Text style={styles.label}>Monthly Income</Text>
                    <View style={styles.inputContainer}>
                        <Text style={styles.currencySymbol}>₱</Text>
                        <TextInput
                            style={styles.input}
                            placeholder="0.00"
                            placeholderTextColor={COLORS.textSecondary}
                            keyboardType="decimal-pad"
                            value={income}
                            onChangeText={setIncome}
                        />
                    </View>
                    <Text style={styles.helperText}>This is your starting balance for the month.</Text>
                </View>

                {/* Savings Rate */}
                <View style={styles.inputGroup}>
                    <Text style={styles.label}>Target Savings Rate (%)</Text>
                    <View style={styles.inputContainer}>
                        <MaterialIcons name="trending-up" size={20} color={COLORS.textSecondary} style={{ marginRight: 8 }} />
                        <TextInput
                            style={styles.input}
                            placeholder="20"
                            placeholderTextColor={COLORS.textSecondary}
                            keyboardType="decimal-pad"
                            value={savingsRate}
                            onChangeText={setSavingsRate}
                        />
                    </View>
                    <Text style={styles.helperText}>The percentage of your income you want to save each month (Recommended: 20%).</Text>
                </View>

                {/* Emergency Fund Goal */}
                <View style={styles.inputGroup}>
                    <Text style={styles.label}>Emergency Fund Goal</Text>
                    <View style={styles.inputContainer}>
                        <Text style={styles.currencySymbol}>₱</Text>
                        <TextInput
                            style={styles.input}
                            placeholder="10000"
                            placeholderTextColor={COLORS.textSecondary}
                            keyboardType="decimal-pad"
                            value={emergencyGoal}
                            onChangeText={setEmergencyGoal}
                        />
                    </View>
                    <Text style={styles.helperText}>Money set aside for unexpected financial emergencies.</Text>
                </View>

                {/* Annual Savings Goal */}
                <View style={styles.inputGroup}>
                    <Text style={styles.label}>Annual Savings Goal</Text>
                    <View style={styles.inputContainer}>
                        <Text style={styles.currencySymbol}>₱</Text>
                        <TextInput
                            style={styles.input}
                            placeholder="50000"
                            placeholderTextColor={COLORS.textSecondary}
                            keyboardType="decimal-pad"
                            value={annualGoal}
                            onChangeText={setAnnualGoal}
                        />
                    </View>
                    <Text style={styles.helperText}>Your target total savings for the current year.</Text>
                </View>

                {/* Save Button */}
                <TouchableOpacity
                    style={[styles.saveButton, saving && styles.disabledButton]}
                    onPress={handleSave}
                    disabled={saving}
                >
                    <Text style={styles.saveButtonText}>
                        {saving ? 'Saving...' : 'Save Changes'}
                    </Text>
                </TouchableOpacity>

            </ScrollView>
        </SafeAreaView>
    );
}

const styles = StyleSheet.create({
    container: {
        flex: 1,
        backgroundColor: COLORS.background,
    },
    center: {
        justifyContent: 'center',
        alignItems: 'center',
    },
    header: {
        flexDirection: 'row',
        alignItems: 'center',
        justifyContent: 'space-between',
        paddingHorizontal: scale(20),
        paddingVertical: verticalScale(16),
    },
    backButton: {
        padding: scale(8),
    },
    headerTitle: {
        fontSize: moderateScale(20),
        fontFamily: 'Poppins-Bold',
        color: COLORS.text,
    },
    scrollView: {
        flex: 1,
    },
    content: {
        padding: scale(20),
        paddingBottom: verticalScale(40),
    },
    inputGroup: {
        marginBottom: verticalScale(24),
    },
    label: {
        fontSize: moderateScale(14),
        fontFamily: 'Poppins-SemiBold',
        color: COLORS.yellow,
        marginBottom: verticalScale(8),
    },
    inputContainer: {
        flexDirection: 'row',
        alignItems: 'center',
        backgroundColor: COLORS.cardBg,
        borderRadius: moderateScale(12),
        paddingHorizontal: scale(16),
    },
    currencySymbol: {
        fontSize: moderateScale(20),
        fontFamily: 'Poppins-Bold',
        color: COLORS.text,
        marginRight: scale(8),
    },
    input: {
        flex: 1,
        fontSize: moderateScale(16),
        fontFamily: 'Poppins-Regular',
        color: COLORS.text,
        paddingVertical: verticalScale(16),
    },
    helperText: {
        fontSize: moderateScale(12),
        fontFamily: 'Poppins-Regular',
        color: COLORS.textSecondary,
        marginTop: verticalScale(4),
        marginLeft: scale(4),
    },
    saveButton: {
        backgroundColor: COLORS.primary,
        borderRadius: moderateScale(12),
        paddingVertical: verticalScale(16),
        alignItems: 'center',
        marginTop: verticalScale(16),
    },
    disabledButton: {
        opacity: 0.6,
    },
    saveButtonText: {
        fontSize: moderateScale(16),
        fontFamily: 'Poppins-Bold',
        color: COLORS.text,
    },
});
