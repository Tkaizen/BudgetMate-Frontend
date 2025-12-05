import React, { useState } from 'react';
import { View, Text, TextInput, TouchableOpacity, StyleSheet, ScrollView, Alert } from 'react-native';
import { SafeAreaView } from 'react-native-safe-area-context';
import { StatusBar } from 'expo-status-bar';
import { useRouter } from 'expo-router';
import { MaterialIcons } from '@expo/vector-icons';
import { scale, verticalScale, moderateScale } from '../src/utils/responsive';
import { api } from '../src/api/api';

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
    'Budgeting',
    'Savings',
    'Side Hustles',
    'Mental Health',
    'Investing',
    'Debt Management',
];

export default function CreatePost() {
    const router = useRouter();
    const [title, setTitle] = useState('');
    const [content, setContent] = useState('');
    const [category, setCategory] = useState('');
    const [errors, setErrors] = useState({});
    const [loading, setLoading] = useState(false);

    const handleSubmit = async () => {
        setErrors({});
        let currentErrors = {};

        if (!title.trim()) currentErrors.title = 'Title is required';
        if (!category) currentErrors.category = 'Category is required';
        if (!content.trim()) currentErrors.content = 'Content is required';

        if (Object.keys(currentErrors).length > 0) {
            setErrors(currentErrors);
            return;
        }

        setLoading(true);

        try {
            await api.post('/api/posts', {
                title,
                content,
                category,
            });

            Alert.alert('Success', 'Post created successfully!', [
                {
                    text: 'OK',
                    onPress: () => router.back(),
                },
            ]);
        } catch (error) {
            console.error('Error creating post:', error);
            Alert.alert('Error', error.response?.data?.msg || 'Failed to create post');
        } finally {
            setLoading(false);
        }
    };

    return (
        <SafeAreaView style={styles.container} edges={['top', 'left', 'right']}>
            <StatusBar style="light" backgroundColor={COLORS.background} />

            {/* Header */}
            <View style={styles.header}>
                <TouchableOpacity onPress={() => router.back()} style={styles.backButton}>
                    <MaterialIcons name="close" size={moderateScale(24)} color={COLORS.text} />
                </TouchableOpacity>
                <Text style={styles.headerTitle}>Create Post</Text>
                <TouchableOpacity
                    onPress={handleSubmit}
                    disabled={loading}
                    style={styles.postButton}
                >
                    <Text style={[styles.postButtonText, loading && styles.postButtonTextDisabled]}>
                        {loading ? 'Posting...' : 'Post'}
                    </Text>
                </TouchableOpacity>
            </View>

            <ScrollView style={styles.scrollView} contentContainerStyle={styles.content}>
                {/* Title Input */}
                <View style={styles.inputGroup}>
                    <Text style={styles.label}>Title *</Text>
                    <TextInput
                        style={[styles.titleInput, errors.title && styles.inputError]}
                        placeholder="What's your question or topic?"
                        placeholderTextColor={COLORS.textSecondary}
                        value={title}
                        onChangeText={(text) => {
                            setTitle(text);
                            if (errors.title) setErrors({ ...errors, title: null });
                        }}
                        maxLength={100}
                    />
                    {errors.title && <Text style={styles.errorText}>{errors.title}</Text>}
                    <Text style={styles.charCount}>{title.length}/100</Text>
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

                {/* Content Input */}
                <View style={styles.inputGroup}>
                    <Text style={styles.label}>Content *</Text>
                    <TextInput
                        style={[styles.contentInput, errors.content && styles.inputError]}
                        placeholder="Share your thoughts, experiences, or ask for advice..."
                        placeholderTextColor={COLORS.textSecondary}
                        multiline
                        value={content}
                        onChangeText={(text) => {
                            setContent(text);
                            if (errors.content) setErrors({ ...errors, content: null });
                        }}
                        maxLength={1000}
                    />
                    {errors.content && <Text style={styles.errorText}>{errors.content}</Text>}
                    <Text style={styles.charCount}>{content.length}/1000</Text>
                </View>

                {/* Tips */}
                <View style={styles.tipsCard}>
                    <Text style={styles.tipsTitle}>💡 Tips for a great post:</Text>
                    <Text style={styles.tipText}>• Be clear and specific</Text>
                    <Text style={styles.tipText}>• Share your experience</Text>
                    <Text style={styles.tipText}>• Be respectful and supportive</Text>
                    <Text style={styles.tipText}>• Use proper grammar</Text>
                </View>
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
        borderBottomWidth: 1,
        borderBottomColor: COLORS.cardBg,
    },
    backButton: {
        padding: scale(8),
    },
    headerTitle: {
        fontSize: moderateScale(20),
        fontFamily: 'Poppins-Bold',
        color: COLORS.text,
    },
    postButton: {
        paddingHorizontal: scale(16),
        paddingVertical: verticalScale(8),
    },
    postButtonText: {
        fontSize: moderateScale(16),
        fontFamily: 'Poppins-Bold',
        color: COLORS.primary,
    },
    postButtonTextDisabled: {
        opacity: 0.5,
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
    titleInput: {
        backgroundColor: COLORS.cardBg,
        borderRadius: moderateScale(12),
        paddingHorizontal: scale(16),
        paddingVertical: verticalScale(16),
        fontSize: moderateScale(16),
        fontFamily: 'Poppins-SemiBold',
        color: COLORS.text,
    },
    contentInput: {
        backgroundColor: COLORS.cardBg,
        borderRadius: moderateScale(12),
        paddingHorizontal: scale(16),
        paddingVertical: verticalScale(16),
        fontSize: moderateScale(15),
        fontFamily: 'Poppins-Regular',
        color: COLORS.text,
        minHeight: verticalScale(200),
        textAlignVertical: 'top',
    },
    charCount: {
        fontSize: moderateScale(12),
        fontFamily: 'Poppins-Regular',
        color: COLORS.textSecondary,
        textAlign: 'right',
        marginTop: verticalScale(4),
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
    tipsCard: {
        backgroundColor: COLORS.cardBg,
        borderRadius: moderateScale(12),
        padding: scale(16),
        marginTop: verticalScale(8),
    },
    tipsTitle: {
        fontSize: moderateScale(14),
        fontFamily: 'Poppins-SemiBold',
        color: COLORS.yellow,
        marginBottom: verticalScale(8),
    },
    tipText: {
        fontSize: moderateScale(13),
        fontFamily: 'Poppins-Regular',
        color: COLORS.textSecondary,
        marginBottom: verticalScale(4),
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
