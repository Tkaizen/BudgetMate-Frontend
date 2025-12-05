import React, { useState } from 'react';
import { View, Text, TextInput, TouchableOpacity, StyleSheet, ScrollView, Alert, Platform } from 'react-native';
import { SafeAreaView } from 'react-native-safe-area-context';
import { StatusBar } from 'expo-status-bar';
import { useRouter } from 'expo-router';
import { MaterialIcons } from '@expo/vector-icons';
import { scale, verticalScale, moderateScale } from '../../src/utils/responsive';
import { api } from '../../src/api/api';
import DateTimePicker from '@react-native-community/datetimepicker';

const COLORS = {
    background: '#141326',
    cardBg: '#433DA3',
    primary: '#E3823C',
    accent: '#E33C3C',
    text: '#FFFFFF',
    textSecondary: '#D7C7EC',
    yellow: '#FFC107',
};

const CATEGORIES = [
    'Housing',
    'Food',
    'Transportation',
    'Utilities',
    'Entertainment',
    'Healthcare',
    'Shopping',
    'Subscription',
    'Savings',
    'Other',
];

export default function AddExpense() {
    const router = useRouter();
    const [amount, setAmount] = useState('');
    const [category, setCategory] = useState('');
    const [description, setDescription] = useState('');
    const [date, setDate] = useState(new Date());
    const [showDatePicker, setShowDatePicker] = useState(false);
    const [errors, setErrors] = useState({});
    const [loading, setLoading] = useState(false);

    const handleSubmit = async () => {
        setErrors({});
        let currentErrors = {};

        if (!amount) {
            currentErrors.amount = 'Amount is required';
        } else if (isNaN(parseFloat(amount)) || parseFloat(amount) <= 0) {
            currentErrors.amount = 'Enter a valid amount';
        }

        if (!category) {
            currentErrors.category = 'Category is required';
        }

        if (Object.keys(currentErrors).length > 0) {
            setErrors(currentErrors);
            return;
        }

        setLoading(true);

        try {
            const response = await api.post('/api/expenses', {
                amount: parseFloat(amount),
                category,
                description,
                date: date.toISOString(),
            });

            Alert.alert('Success', 'Expense added successfully!', [
                {
                    text: 'OK',
                    onPress: () => router.back(),
                },
            ]);
        } catch (error) {
            console.error('Error adding expense:', error);
            Alert.alert('Error', error.response?.data?.msg || 'Failed to add expense');
        } finally {
            setLoading(false);
        }
    };

    const onDateChange = (event, selectedDate) => {
        setShowDatePicker(Platform.OS === 'ios');
        if (selectedDate) {
            setDate(selectedDate);
        }
    };

    return (
        <SafeAreaView style={styles.container} edges={['top', 'left', 'right']}>
            <StatusBar style="light" backgroundColor={COLORS.background} />

            {/* Header */}
            <View style={styles.header}>
                <TouchableOpacity onPress={() => router.back()} style={styles.backButton}>
                    <MaterialIcons name="arrow-back" size={moderateScale(24)} color={COLORS.text} />
                </TouchableOpacity>
                <Text style={styles.headerTitle}>Add Expense</Text>
                <View style={{ width: moderateScale(24) }} />
            </View>

            <ScrollView style={styles.scrollView} contentContainerStyle={styles.content}>
                {/* Amount Input */}
                <View style={styles.inputGroup}>
                    <Text style={styles.label}>Amount *</Text>
                    <View style={[styles.inputContainer, errors.amount && styles.inputError]}>
                        <Text style={styles.currencySymbol}>₱</Text>
                        <TextInput
                            style={styles.input}
                            placeholder="0.00"
                            placeholderTextColor={COLORS.textSecondary}
                            keyboardType="decimal-pad"
                            value={amount}
                            onChangeText={(text) => {
                                setAmount(text);
                                if (errors.amount) setErrors({ ...errors, amount: null });
                            }}
                        />
                    </View>
                    {errors.amount && <Text style={styles.errorText}>{errors.amount}</Text>}
                </View>

                {/* Category Selection */}
                <View style={styles.inputGroup}>
                    <Text style={styles.label}>Category *</Text>
                    <ScrollView horizontal showsHorizontalScrollIndicator={false} style={styles.categoryScroll}>
                        {CATEGORIES.map((cat) => (
                            <TouchableOpacity
                                key={cat}
                                style={[
                                    styles.categoryChip,
                                    category === cat && styles.categoryChipActive,
                                    errors.category && styles.categoryChipError
                                ]}
                                onPress={() => {
                                    setCategory(cat);
                                    if (errors.category) setErrors({ ...errors, category: null });
                                }}
                            >
                                <Text
                                    style={[
                                        styles.categoryChipText,
                                        category === cat && styles.categoryChipTextActive,
                                    ]}
                                >
                                    {cat}
                                </Text>
                            </TouchableOpacity>
                        ))}
                    </ScrollView>
                    {errors.category && <Text style={styles.errorText}>{errors.category}</Text>}
                </View>

                {/* Date Picker */}
                <View style={styles.inputGroup}>
                    <Text style={styles.label}>Date</Text>
                    <TouchableOpacity
                        style={styles.dateButton}
                        onPress={() => setShowDatePicker(true)}
                    >
                        <MaterialIcons name="calendar-today" size={moderateScale(20)} color={COLORS.textSecondary} />
                        <Text style={styles.dateText}>
                            {date.toLocaleDateString('en-US', { month: 'short', day: 'numeric', year: 'numeric' })}
                        </Text>
                    </TouchableOpacity>
                </View>

                {showDatePicker && (
                    <DateTimePicker
                        value={date}
                        mode="date"
                        display={Platform.OS === 'ios' ? 'spinner' : 'default'}
                        onChange={onDateChange}
                        maximumDate={new Date()}
                    />
                )}

                {/* Description Input */}
                <View style={styles.inputGroup}>
                    <Text style={styles.label}>Description (Optional)</Text>
                    <TextInput
                        style={[styles.input, styles.textArea]}
                        placeholder="Add a note..."
                        placeholderTextColor={COLORS.textSecondary}
                        multiline
                        numberOfLines={4}
                        value={description}
                        onChangeText={setDescription}
                    />
                </View>

                {/* Submit Button */}
                <TouchableOpacity
                    style={[styles.submitButton, loading && styles.submitButtonDisabled]}
                    onPress={handleSubmit}
                    disabled={loading}
                >
                    <Text style={styles.submitButtonText}>
                        {loading ? 'Adding...' : 'Add Expense'}
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
    textArea: {
        backgroundColor: COLORS.cardBg,
        borderRadius: moderateScale(12),
        paddingHorizontal: scale(16),
        paddingVertical: verticalScale(12),
        textAlignVertical: 'top',
        minHeight: verticalScale(100),
    },
    categoryScroll: {
        flexGrow: 0,
    },
    categoryChip: {
        backgroundColor: 'transparent',
        borderWidth: 1,
        borderColor: COLORS.textSecondary,
        borderRadius: moderateScale(20),
        paddingHorizontal: scale(16),
        paddingVertical: verticalScale(8),
        marginRight: scale(8),
    },
    categoryChipActive: {
        backgroundColor: COLORS.yellow,
        borderColor: COLORS.yellow,
    },
    categoryChipText: {
        fontSize: moderateScale(14),
        fontFamily: 'Poppins-Medium',
        color: COLORS.textSecondary,
    },
    categoryChipTextActive: {
        color: COLORS.background,
        fontFamily: 'Poppins-SemiBold',
    },
    dateButton: {
        flexDirection: 'row',
        alignItems: 'center',
        backgroundColor: COLORS.cardBg,
        borderRadius: moderateScale(12),
        paddingHorizontal: scale(16),
        paddingVertical: verticalScale(16),
    },
    dateText: {
        fontSize: moderateScale(16),
        fontFamily: 'Poppins-Regular',
        color: COLORS.text,
        marginLeft: scale(12),
    },
    submitButton: {
        backgroundColor: COLORS.primary,
        borderRadius: moderateScale(12),
        paddingVertical: verticalScale(16),
        alignItems: 'center',
        marginTop: verticalScale(16),
    },
    submitButtonDisabled: {
        opacity: 0.6,
    },
    submitButtonText: {
        fontSize: moderateScale(16),
        fontFamily: 'Poppins-Bold',
        color: COLORS.text,
    },
    inputError: {
        borderWidth: 1,
        borderColor: COLORS.accent,
    },
    categoryChipError: {
        borderColor: COLORS.accent,
    },
    errorText: {
        color: COLORS.accent,
        fontSize: moderateScale(12),
        fontFamily: 'Poppins-Regular',
        marginTop: verticalScale(4),
    },
});
