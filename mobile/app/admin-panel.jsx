import React, { useState, useEffect } from 'react';
import {
    View,
    Text,
    ScrollView,
    TouchableOpacity,
    TextInput,
    ActivityIndicator,
    Alert,
    KeyboardAvoidingView,
    Platform,
} from 'react-native';
import { SafeAreaView } from 'react-native-safe-area-context';
import { StatusBar } from 'expo-status-bar';
import { useRouter } from 'expo-router';
import { MaterialIcons } from '@expo/vector-icons';
import {
    fetchArticles,
    createArticle,
    updateArticle,
    deleteArticle,
} from '../src/api/api';
import { styles, COLORS } from './admin-panel-styles';

const AdminPanel = () => {
    const router = useRouter();
    const [articles, setArticles] = useState([]);
    const [loading, setLoading] = useState(true);
    const [submitting, setSubmitting] = useState(false);

    // Article form state
    const [articleForm, setArticleForm] = useState({
        title: '',
        description: '',
        url: '',
        iconName: 'article',
        color: '#6C63FF',
        category: 'general',
    });

    // Edit mode state
    const [editingArticle, setEditingArticle] = useState(null);

    // Check if user is admin
    useEffect(() => {
        const userData = global.userData;
        if (!userData || userData.role !== 'admin') {
            Alert.alert('Access Denied', 'You do not have admin privileges.', [
                { text: 'OK', onPress: () => router.back() },
            ]);
            return;
        }
        loadArticles();
    }, []);

    // Load articles
    const loadArticles = async () => {
        try {
            const data = await fetchArticles();
            setArticles(data.articles || []);
        } catch (err) {
            console.error('Error loading articles:', err);
            Alert.alert('Error', 'Failed to load articles');
        } finally {
            setLoading(false);
        }
    };

    // Handle article form submission
    const handleCreateArticle = async () => {
        // Validation
        if (!articleForm.title.trim() || !articleForm.description.trim()) {
            Alert.alert('Validation Error', 'Title and description are required');
            return;
        }

        setSubmitting(true);
        try {
            await createArticle(articleForm);
            Alert.alert('Success', 'Article created successfully!');
            // Reset form
            setArticleForm({
                title: '',
                description: '',
                url: '',
                iconName: 'article',
                color: '#6C63FF',
                category: 'general',
            });
            // Reload articles
            loadArticles();
        } catch (err) {
            console.error('Error creating article:', err);
            Alert.alert('Error', err.response?.data?.message || 'Failed to create article');
        } finally {
            setSubmitting(false);
        }
    };

    // Handle article update
    const handleUpdateArticle = async () => {
        // Validation
        if (!articleForm.title.trim() || !articleForm.description.trim()) {
            Alert.alert('Validation Error', 'Title and description are required');
            return;
        }

        setSubmitting(true);
        try {
            await updateArticle(editingArticle._id, articleForm);
            Alert.alert('Success', 'Article updated successfully!');
            // Reset form and exit edit mode
            setArticleForm({
                title: '',
                description: '',
                url: '',
                iconName: 'article',
                color: '#6C63FF',
                category: 'general',
            });
            setEditingArticle(null);
            // Reload articles
            loadArticles();
        } catch (err) {
            console.error('Error updating article:', err);
            Alert.alert('Error', err.response?.data?.message || 'Failed to update article');
        } finally {
            setSubmitting(false);
        }
    };

    // Handle edit button click
    const handleEditArticle = (article) => {
        setEditingArticle(article);
        setArticleForm({
            title: article.title,
            description: article.description,
            url: article.url || '',
            iconName: article.iconName || 'article',
            color: article.color || '#6C63FF',
            category: article.category || 'general',
        });
    };

    // Handle cancel edit
    const handleCancelEdit = () => {
        setEditingArticle(null);
        setArticleForm({
            title: '',
            description: '',
            url: '',
            iconName: 'article',
            color: '#6C63FF',
            category: 'general',
        });
    };

    // Handle article deletion
    const handleDeleteArticle = (id, title) => {
        Alert.alert(
            'Confirm Delete',
            `Are you sure you want to delete "${title}"?`,
            [
                { text: 'Cancel', style: 'cancel' },
                {
                    text: 'Delete',
                    style: 'destructive',
                    onPress: async () => {
                        try {
                            await deleteArticle(id);
                            Alert.alert('Success', 'Article deleted successfully');
                            loadArticles();
                        } catch (err) {
                            console.error('Error deleting article:', err);
                            Alert.alert('Error', 'Failed to delete article');
                        }
                    },
                },
            ]
        );
    };

    if (loading) {
        return (
            <SafeAreaView style={styles.container}>
                <StatusBar style="light" backgroundColor={COLORS.background} />
                <View style={styles.loadingContainer}>
                    <ActivityIndicator size="large" color={COLORS.primary} />
                    <Text style={styles.loadingText}>Loading...</Text>
                </View>
            </SafeAreaView>
        );
    }

    return (
        <SafeAreaView style={styles.container}>
            <StatusBar style="light" backgroundColor={COLORS.background} />

            {/* Header */}
            <View style={styles.header}>
                <TouchableOpacity onPress={() => router.back()} style={styles.backButton}>
                    <MaterialIcons name="arrow-back" size={24} color={COLORS.text} />
                </TouchableOpacity>
                <Text style={styles.title}>Admin Panel</Text>
                <View style={{ width: 24 }} />
            </View>

            <KeyboardAvoidingView
                style={{ flex: 1 }}
                behavior={Platform.OS === 'ios' ? 'padding' : 'height'}
            >
                <ScrollView style={styles.content} showsVerticalScrollIndicator={false}>
                    {/* Add/Edit Article Form */}
                    <View style={styles.section}>
                        <Text style={styles.sectionTitle}>
                            {editingArticle ? 'Edit Article' : 'Add New Article'}
                        </Text>
                        <View style={styles.card}>
                            <TextInput
                                style={styles.input}
                                placeholder="Title *"
                                placeholderTextColor={COLORS.textSecondary}
                                value={articleForm.title}
                                onChangeText={(text) => setArticleForm({ ...articleForm, title: text })}
                            />
                            <TextInput
                                style={[styles.input, styles.textArea]}
                                placeholder="Description *"
                                placeholderTextColor={COLORS.textSecondary}
                                value={articleForm.description}
                                onChangeText={(text) => setArticleForm({ ...articleForm, description: text })}
                                multiline
                                numberOfLines={3}
                            />
                            <TextInput
                                style={styles.input}
                                placeholder="URL (optional)"
                                placeholderTextColor={COLORS.textSecondary}
                                value={articleForm.url}
                                onChangeText={(text) => setArticleForm({ ...articleForm, url: text })}
                                autoCapitalize="none"
                            />
                            <TextInput
                                style={styles.input}
                                placeholder="Icon Name (e.g., article, savings)"
                                placeholderTextColor={COLORS.textSecondary}
                                value={articleForm.iconName}
                                onChangeText={(text) => setArticleForm({ ...articleForm, iconName: text })}
                            />
                            <TextInput
                                style={styles.input}
                                placeholder="Color (e.g., #6C63FF)"
                                placeholderTextColor={COLORS.textSecondary}
                                value={articleForm.color}
                                onChangeText={(text) => setArticleForm({ ...articleForm, color: text })}
                            />
                            <TouchableOpacity
                                style={[styles.button, submitting && styles.buttonDisabled]}
                                onPress={editingArticle ? handleUpdateArticle : handleCreateArticle}
                                disabled={submitting}
                            >
                                {submitting ? (
                                    <ActivityIndicator color="#FFFFFF" />
                                ) : (
                                    <>
                                        <MaterialIcons
                                            name={editingArticle ? 'save' : 'add'}
                                            size={20}
                                            color="#FFFFFF"
                                        />
                                        <Text style={styles.buttonText}>
                                            {editingArticle ? 'Update Article' : 'Create Article'}
                                        </Text>
                                    </>
                                )}
                            </TouchableOpacity>
                            {editingArticle && (
                                <TouchableOpacity
                                    style={[styles.button, styles.cancelButton]}
                                    onPress={handleCancelEdit}
                                >
                                    <MaterialIcons name="close" size={20} color="#FFFFFF" />
                                    <Text style={styles.buttonText}>Cancel</Text>
                                </TouchableOpacity>
                            )}
                        </View>
                    </View>

                    {/* Articles List */}
                    <View style={styles.section}>
                        <Text style={styles.sectionTitle}>Existing Articles ({articles.length})</Text>
                        {articles.map((article) => (
                            <View key={article._id} style={styles.articleCard}>
                                <View style={styles.articleHeader}>
                                    <MaterialIcons
                                        name={article.iconName || 'article'}
                                        size={24}
                                        color={article.color || COLORS.primary}
                                    />
                                    <View style={styles.articleInfo}>
                                        <Text style={styles.articleTitle}>{article.title}</Text>
                                        <Text style={styles.articleDescription} numberOfLines={2}>
                                            {article.description}
                                        </Text>
                                    </View>
                                </View>
                                <View style={styles.articleActions}>
                                    <TouchableOpacity
                                        style={styles.editButton}
                                        onPress={() => handleEditArticle(article)}
                                    >
                                        <MaterialIcons name="edit" size={20} color={COLORS.primary} />
                                    </TouchableOpacity>
                                    <TouchableOpacity
                                        style={styles.deleteButton}
                                        onPress={() => handleDeleteArticle(article._id, article.title)}
                                    >
                                        <MaterialIcons name="delete" size={20} color={COLORS.red} />
                                    </TouchableOpacity>
                                </View>
                            </View>
                        ))}
                    </View>
                </ScrollView>
            </KeyboardAvoidingView>
        </SafeAreaView>
    );
};

export default AdminPanel;
