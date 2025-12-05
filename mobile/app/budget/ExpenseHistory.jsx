import React, { useState, useCallback } from 'react';
import { View, Text, FlatList, TouchableOpacity, StyleSheet, Alert, RefreshControl } from 'react-native';
import { SafeAreaView } from 'react-native-safe-area-context';
import { StatusBar } from 'expo-status-bar';
import { useRouter, useFocusEffect } from 'expo-router';
import { MaterialIcons } from '@expo/vector-icons';
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

export default function ExpenseHistory() {
    const router = useRouter();
    const [expenses, setExpenses] = useState([]);
    const [loading, setLoading] = useState(true);
    const [refreshing, setRefreshing] = useState(false);

    useFocusEffect(
        useCallback(() => {
            loadExpenses();
        }, [])
    );

    const loadExpenses = async () => {
        try {
            const response = await api.get('/api/expenses');
            setExpenses(response.data);
        } catch (error) {
            console.error('Error loading expenses:', error);
            Alert.alert('Error', 'Failed to load expenses');
        } finally {
            setLoading(false);
            setRefreshing(false);
        }
    };

    const onRefresh = () => {
        setRefreshing(true);
        loadExpenses();
    };

    const handleDelete = (id) => {
        Alert.alert(
            'Delete Expense',
            'Are you sure you want to delete this expense?',
            [
                { text: 'Cancel', style: 'cancel' },
                {
                    text: 'Delete',
                    style: 'destructive',
                    onPress: async () => {
                        try {
                            await api.delete(`/api/expenses/${id}`);
                            setExpenses(expenses.filter(exp => exp._id !== id));
                            Alert.alert('Success', 'Expense deleted');
                        } catch (error) {
                            console.error('Error deleting expense:', error);
                            Alert.alert('Error', 'Failed to delete expense');
                        }
                    },
                },
            ]
        );
    };

    const renderExpenseItem = ({ item }) => {
        const date = new Date(item.date);
        const formattedDate = date.toLocaleDateString('en-US', {
            month: 'short',
            day: 'numeric',
            year: 'numeric',
            hour: 'numeric',
            minute: '2-digit'
        });

        return (
            <View style={styles.expenseCard}>
                <View style={styles.expenseHeader}>
                    <View style={styles.categoryBadge}>
                        <Text style={styles.categoryText}>{item.category}</Text>
                    </View>
                    <Text style={styles.dateText}>{formattedDate}</Text>
                </View>

                <View style={styles.expenseBody}>
                    <View style={styles.expenseInfo}>
                        <Text style={styles.amountText}>₱{item.amount.toLocaleString()}</Text>
                        {item.description ? (
                            <Text style={styles.descriptionText} numberOfLines={2}>
                                {item.description}
                            </Text>
                        ) : null}
                    </View>

                    <TouchableOpacity
                        style={styles.deleteButton}
                        onPress={() => handleDelete(item._id)}
                    >
                        <MaterialIcons name="delete-outline" size={moderateScale(24)} color={COLORS.accent} />
                    </TouchableOpacity>
                </View>
            </View>
        );
    };

    const renderEmptyState = () => (
        <View style={styles.emptyState}>
            <MaterialIcons name="receipt-long" size={moderateScale(64)} color={COLORS.textSecondary} />
            <Text style={styles.emptyStateText}>No expenses yet</Text>
            <Text style={styles.emptyStateSubtext}>Start tracking your expenses</Text>
        </View>
    );

    const totalExpenses = expenses.reduce((sum, exp) => sum + exp.amount, 0);

    return (
        <SafeAreaView style={styles.container} edges={['top', 'left', 'right']}>
            <StatusBar style="light" backgroundColor={COLORS.background} />

            {/* Header */}
            <View style={styles.header}>
                <TouchableOpacity onPress={() => router.back()} style={styles.backButton}>
                    <MaterialIcons name="arrow-back" size={moderateScale(24)} color={COLORS.text} />
                </TouchableOpacity>
                <Text style={styles.headerTitle}>Expense History</Text>
                <TouchableOpacity onPress={() => router.push('/AddExpense')} style={styles.addButton}>
                    <MaterialIcons name="add" size={moderateScale(24)} color={COLORS.text} />
                </TouchableOpacity>
            </View>

            {/* Total Summary */}
            <View style={styles.summaryCard}>
                <Text style={styles.summaryLabel}>Total Expenses</Text>
                <Text style={styles.summaryAmount}>₱{totalExpenses.toLocaleString()}</Text>
                <Text style={styles.summarySubtext}>{expenses.length} transactions</Text>
            </View>

            {/* Expense List */}
            <FlatList
                data={expenses}
                renderItem={renderExpenseItem}
                keyExtractor={(item) => item._id}
                contentContainerStyle={styles.listContent}
                ListEmptyComponent={!loading && renderEmptyState}
                refreshControl={
                    <RefreshControl
                        refreshing={refreshing}
                        onRefresh={onRefresh}
                        tintColor={COLORS.primary}
                        colors={[COLORS.primary]}
                    />
                }
            />
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
    addButton: {
        padding: scale(8),
    },
    headerTitle: {
        fontSize: moderateScale(20),
        fontFamily: 'Poppins-Bold',
        color: COLORS.text,
    },
    summaryCard: {
        backgroundColor: COLORS.cardBg,
        marginHorizontal: scale(20),
        marginBottom: verticalScale(16),
        padding: scale(20),
        borderRadius: moderateScale(16),
        alignItems: 'center',
    },
    summaryLabel: {
        fontSize: moderateScale(14),
        fontFamily: 'Poppins-Regular',
        color: COLORS.textSecondary,
    },
    summaryAmount: {
        fontSize: moderateScale(32),
        fontFamily: 'Poppins-Bold',
        color: COLORS.yellow,
        marginVertical: verticalScale(8),
    },
    summarySubtext: {
        fontSize: moderateScale(12),
        fontFamily: 'Poppins-Regular',
        color: COLORS.textSecondary,
    },
    listContent: {
        paddingHorizontal: scale(20),
        paddingBottom: verticalScale(20),
    },
    expenseCard: {
        backgroundColor: COLORS.cardBg,
        borderRadius: moderateScale(12),
        padding: scale(16),
        marginBottom: verticalScale(12),
    },
    expenseHeader: {
        flexDirection: 'row',
        justifyContent: 'space-between',
        alignItems: 'center',
        marginBottom: verticalScale(12),
    },
    categoryBadge: {
        backgroundColor: COLORS.yellow,
        paddingHorizontal: scale(12),
        paddingVertical: verticalScale(4),
        borderRadius: moderateScale(12),
    },
    categoryText: {
        fontSize: moderateScale(12),
        fontFamily: 'Poppins-SemiBold',
        color: COLORS.background,
    },
    dateText: {
        fontSize: moderateScale(12),
        fontFamily: 'Poppins-Regular',
        color: COLORS.textSecondary,
    },
    expenseBody: {
        flexDirection: 'row',
        justifyContent: 'space-between',
        alignItems: 'center',
    },
    expenseInfo: {
        flex: 1,
    },
    amountText: {
        fontSize: moderateScale(20),
        fontFamily: 'Poppins-Bold',
        color: COLORS.text,
        marginBottom: verticalScale(4),
    },
    descriptionText: {
        fontSize: moderateScale(14),
        fontFamily: 'Poppins-Regular',
        color: COLORS.textSecondary,
    },
    deleteButton: {
        padding: scale(8),
    },
    emptyState: {
        alignItems: 'center',
        justifyContent: 'center',
        paddingVertical: verticalScale(60),
    },
    emptyStateText: {
        fontSize: moderateScale(18),
        fontFamily: 'Poppins-SemiBold',
        color: COLORS.text,
        marginTop: verticalScale(16),
    },
    emptyStateSubtext: {
        fontSize: moderateScale(14),
        fontFamily: 'Poppins-Regular',
        color: COLORS.textSecondary,
        marginTop: verticalScale(4),
    },
});
