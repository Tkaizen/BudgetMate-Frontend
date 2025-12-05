import React from 'react';
import { View, Text, StyleSheet } from 'react-native';
import { MaterialIcons } from '@expo/vector-icons';
import { scale, verticalScale, moderateScale } from '../../utils/responsive';

const COLORS = {
    background: '#141326',
    cardBg: '#2A265C',
    primary: '#E3823C',
    text: '#FFFFFF',
    textSecondary: '#D7C7EC',
};

const TransactionCard = ({ item }) => {
    return (
        <View style={styles.transactionCard}>
            <View style={[styles.categoryIcon, { backgroundColor: 'rgba(227, 130, 60, 0.15)' }]}>
                <MaterialIcons name="shopping-bag" size={20} color={COLORS.primary} />
            </View>
            <View style={styles.transactionInfo}>
                <Text style={styles.transactionTitle}>{item.category}</Text>
                <Text style={styles.transactionDate}>
                    {new Date(item.date).toLocaleDateString('en-US', { month: 'short', day: 'numeric' })} • {new Date(item.date).toLocaleTimeString('en-US', { hour: 'numeric', minute: '2-digit' })}
                </Text>
            </View>
            <Text style={styles.transactionAmount}>-₱{item.amount.toLocaleString()}</Text>
        </View>
    );
};

const styles = StyleSheet.create({
    transactionCard: {
        flexDirection: 'row',
        alignItems: 'center',
        backgroundColor: COLORS.cardBg,
        padding: scale(16),
        borderRadius: moderateScale(16),
        marginBottom: verticalScale(12),
    },
    categoryIcon: {
        width: moderateScale(40),
        height: moderateScale(40),
        borderRadius: moderateScale(12),
        justifyContent: 'center',
        alignItems: 'center',
        marginRight: scale(12),
    },
    transactionInfo: {
        flex: 1,
    },
    transactionTitle: {
        fontSize: moderateScale(16),
        fontFamily: 'Poppins-Medium',
        color: COLORS.text,
    },
    transactionDate: {
        fontSize: moderateScale(12),
        fontFamily: 'Poppins-Regular',
        color: COLORS.textSecondary,
    },
    transactionAmount: {
        fontSize: moderateScale(16),
        fontFamily: 'Poppins-SemiBold',
        color: COLORS.text,
    },
});

export default TransactionCard;
