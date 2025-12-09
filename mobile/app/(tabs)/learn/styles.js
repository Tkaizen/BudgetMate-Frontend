import { StyleSheet } from 'react-native';
import { scale, verticalScale, moderateScale } from '../../../src/utils/responsive';

export const COLORS = {
    background: '#141326',
    text: '#FFFFFF',
    textSecondary: '#D7C7EC',
    primary: '#E3823C',
    blue: '#433DA3',
    green: '#4CAF50',
    red: '#E33C3C',
};

export const styles = StyleSheet.create({
    container: {
        flex: 1,
        backgroundColor: COLORS.background,
    },
    header: {
        paddingHorizontal: scale(20),
        paddingTop: verticalScale(20),
        paddingBottom: verticalScale(10),
    },
    title: {
        fontSize: moderateScale(28),
        fontFamily: 'Poppins-Bold',
        color: COLORS.text,
    },
    subtitle: {
        fontSize: moderateScale(14),
        fontFamily: 'Poppins-Regular',
        color: COLORS.textSecondary,
        marginTop: verticalScale(-4),
    },
    scrollView: {
        flex: 1,
    },
    content: {
        padding: scale(20),
        paddingTop: verticalScale(10),
    },
    loadingContainer: {
        flex: 1,
        justifyContent: 'center',
        alignItems: 'center',
    },
    loadingText: {
        fontSize: moderateScale(14),
        fontFamily: 'Poppins-Regular',
        color: COLORS.textSecondary,
        marginTop: verticalScale(12),
    },
    errorContainer: {
        marginHorizontal: scale(20),
        marginBottom: verticalScale(10),
        padding: scale(12),
        backgroundColor: '#E33C3C20',
        borderRadius: moderateScale(8),
        borderLeftWidth: 4,
        borderLeftColor: COLORS.red,
    },
    errorText: {
        fontSize: moderateScale(13),
        fontFamily: 'Poppins-Regular',
        color: COLORS.red,
    },
    emptyContainer: {
        flex: 1,
        justifyContent: 'center',
        alignItems: 'center',
        paddingVertical: verticalScale(60),
    },
    emptyText: {
        fontSize: moderateScale(16),
        fontFamily: 'Poppins-SemiBold',
        color: COLORS.textSecondary,
        marginTop: verticalScale(16),
    },
    emptySubtext: {
        fontSize: moderateScale(13),
        fontFamily: 'Poppins-Regular',
        color: COLORS.textSecondary,
        marginTop: verticalScale(8),
        textAlign: 'center',
    },
    fab: {
        position: 'absolute',
        bottom: verticalScale(24),
        right: scale(24),
        width: moderateScale(60),
        height: moderateScale(60),
        borderRadius: moderateScale(30),
        backgroundColor: COLORS.primary,
        justifyContent: 'center',
        alignItems: 'center',
        shadowColor: '#000',
        shadowOffset: { width: 0, height: 4 },
        shadowOpacity: 0.3,
        shadowRadius: 8,
        elevation: 8,
    },
});
