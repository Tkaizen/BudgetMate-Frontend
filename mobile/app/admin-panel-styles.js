import { StyleSheet } from 'react-native';
import { scale, verticalScale, moderateScale } from '../src/utils/responsive';

export const COLORS = {
    background: '#141326',
    cardBg: '#2A265C',
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
    header: {
        flexDirection: 'row',
        alignItems: 'center',
        justifyContent: 'space-between',
        paddingHorizontal: scale(20),
        paddingVertical: verticalScale(16),
        borderBottomWidth: 1,
        borderBottomColor: '#2A265C',
    },
    backButton: {
        padding: scale(4),
    },
    title: {
        fontSize: moderateScale(24),
        fontFamily: 'Poppins-Bold',
        color: COLORS.text,
    },
    tabContainer: {
        flexDirection: 'row',
        paddingHorizontal: scale(20),
        paddingTop: verticalScale(16),
        gap: scale(12),
    },
    tab: {
        flex: 1,
        flexDirection: 'row',
        alignItems: 'center',
        justifyContent: 'center',
        paddingVertical: verticalScale(12),
        paddingHorizontal: scale(16),
        backgroundColor: COLORS.cardBg,
        borderRadius: moderateScale(12),
        gap: scale(8),
    },
    activeTab: {
        backgroundColor: `${COLORS.primary}20`,
        borderWidth: 1,
        borderColor: COLORS.primary,
    },
    tabText: {
        fontSize: moderateScale(13),
        fontFamily: 'Poppins-Medium',
        color: COLORS.textSecondary,
    },
    activeTabText: {
        color: COLORS.primary,
    },
    content: {
        flex: 1,
        paddingHorizontal: scale(20),
    },
    section: {
        marginTop: verticalScale(20),
        marginBottom: verticalScale(20),
    },
    sectionTitle: {
        fontSize: moderateScale(18),
        fontFamily: 'Poppins-SemiBold',
        color: COLORS.text,
        marginBottom: verticalScale(12),
    },
    card: {
        backgroundColor: COLORS.cardBg,
        borderRadius: moderateScale(16),
        padding: scale(20),
        gap: verticalScale(12),
    },
    input: {
        backgroundColor: '#1A1733',
        borderRadius: moderateScale(12),
        padding: scale(14),
        fontSize: moderateScale(14),
        fontFamily: 'Poppins-Regular',
        color: COLORS.text,
        borderWidth: 1,
        borderColor: '#3A3566',
    },
    textArea: {
        minHeight: verticalScale(80),
        textAlignVertical: 'top',
    },
    button: {
        flexDirection: 'row',
        alignItems: 'center',
        justifyContent: 'center',
        backgroundColor: COLORS.primary,
        borderRadius: moderateScale(12),
        paddingVertical: verticalScale(14),
        gap: scale(8),
        marginTop: verticalScale(8),
    },
    buttonDisabled: {
        opacity: 0.6,
    },
    buttonText: {
        fontSize: moderateScale(15),
        fontFamily: 'Poppins-SemiBold',
        color: '#FFFFFF',
    },
    articleCard: {
        flexDirection: 'row',
        alignItems: 'center',
        justifyContent: 'space-between',
        backgroundColor: COLORS.cardBg,
        borderRadius: moderateScale(12),
        padding: scale(16),
        marginBottom: verticalScale(12),
    },
    articleHeader: {
        flexDirection: 'row',
        alignItems: 'center',
        flex: 1,
        gap: scale(12),
    },
    articleInfo: {
        flex: 1,
    },
    articleTitle: {
        fontSize: moderateScale(15),
        fontFamily: 'Poppins-SemiBold',
        color: COLORS.text,
        marginBottom: verticalScale(4),
    },
    articleDescription: {
        fontSize: moderateScale(12),
        fontFamily: 'Poppins-Regular',
        color: COLORS.textSecondary,
    },
    deleteButton: {
        padding: scale(8),
        marginLeft: scale(8),
    },
    editButton: {
        padding: scale(8),
        marginRight: scale(8),
    },
    articleActions: {
        flexDirection: 'row',
        alignItems: 'center',
    },
    cancelButton: {
        backgroundColor: COLORS.red,
        marginTop: verticalScale(8),
    },
    inputWithIcon: {
        paddingRight: scale(45),
    },
    eyeIcon: {
        position: 'absolute',
        right: scale(14),
        top: verticalScale(14),
        padding: scale(5),
        zIndex: 10,
    },
});
