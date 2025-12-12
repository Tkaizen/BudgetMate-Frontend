import React, { useState, useEffect } from 'react';
import {
    View,
    Text,
    TextInput,
    TouchableOpacity,
    ScrollView,
    Alert,
    Modal,
    KeyboardAvoidingView,
    Platform,
    StyleSheet,
    Switch
} from 'react-native';
import { LinearGradient } from 'expo-linear-gradient';
import { Ionicons } from '@expo/vector-icons';
import { moderateScale, verticalScale, scale } from '../utils/responsive';
import { createJob, updateJob } from '../api/api';

const COLORS = {
    background: '#141326',
    cardBg: '#433DA3',
    primary: '#E3823C',
    text: '#FFFFFF',
    textSecondary: '#D7C7EC',
    yellow: '#FFC107',
    inputBg: '#2B2769',
};

const JobFormModal = ({ visible, job, onClose }) => {
    const [formData, setFormData] = useState({
        title: '',
        description: '',
        difficulty: 'Easy',
        payRange: '',
        timeCommitment: '',
        tags: '',
        fullDescription: '',
        requirements: '',
        howToStart: '',
        isPublished: true,
    });
    const [loading, setLoading] = useState(false);

    useEffect(() => {
        if (job) {
            // Editing existing job
            setFormData({
                title: job.title || '',
                description: job.description || '',
                difficulty: job.difficulty || 'Easy',
                payRange: job.payRange || '',
                timeCommitment: job.timeCommitment || '',
                tags: Array.isArray(job.tags) ? job.tags.join(', ') : '',
                fullDescription: job.fullDescription || '',
                requirements: Array.isArray(job.requirements) ? job.requirements.join('\n') : '',
                howToStart: job.howToStart || '',
                isPublished: job.isPublished !== undefined ? job.isPublished : true,
            });
        } else {
            // Creating new job
            setFormData({
                title: '',
                description: '',
                difficulty: 'Easy',
                payRange: '',
                timeCommitment: '',
                tags: '',
                fullDescription: '',
                requirements: '',
                howToStart: '',
                isPublished: true,
            });
        }
    }, [job, visible]);

    const handleSubmit = async () => {
        // Validation
        if (!formData.title.trim() || !formData.description.trim() ||
            !formData.payRange.trim() || !formData.timeCommitment.trim()) {
            Alert.alert('Error', 'Please fill in all required fields (Title, Description, Pay Range, Time Commitment)');
            return;
        }

        setLoading(true);
        try {
            const jobData = {
                title: formData.title.trim(),
                description: formData.description.trim(),
                difficulty: formData.difficulty,
                payRange: formData.payRange.trim(),
                timeCommitment: formData.timeCommitment.trim(),
                tags: formData.tags.split(',').map(tag => tag.trim()).filter(tag => tag),
                fullDescription: formData.fullDescription.trim(),
                requirements: formData.requirements.split('\n').map(req => req.trim()).filter(req => req),
                howToStart: formData.howToStart.trim(),
                isPublished: formData.isPublished,
            };

            if (job) {
                // Update existing job
                await updateJob(job._id, jobData);
                Alert.alert('Success', 'Job updated successfully');
            } else {
                // Create new job
                await createJob(jobData);
                Alert.alert('Success', 'Job created successfully');
            }

            onClose(true); // true indicates refresh is needed
        } catch (error) {
            console.error('Error saving job:', error);
            Alert.alert('Error', error.response?.data?.message || 'Failed to save job');
        } finally {
            setLoading(false);
        }
    };

    const updateField = (field, value) => {
        setFormData(prev => ({ ...prev, [field]: value }));
    };

    return (
        <Modal
            animationType="slide"
            transparent={true}
            visible={visible}
            onRequestClose={() => onClose(false)}
        >
            <KeyboardAvoidingView
                behavior={Platform.OS === "ios" ? "padding" : "height"}
                style={styles.modalOverlay}
            >
                <View style={styles.modalContent}>
                    <LinearGradient
                        colors={['#433DA3', '#2B2769', '#19173D']}
                        locations={[0.1, 0.45, 0.75]}
                        style={styles.gradientFill}
                    />

                    <View style={styles.modalHeader}>
                        <Text style={styles.modalTitle}>
                            {job ? 'Edit Job' : 'Create New Job'}
                        </Text>
                        <TouchableOpacity onPress={() => onClose(false)}>
                            <Ionicons name="close" size={24} color={COLORS.text} />
                        </TouchableOpacity>
                    </View>

                    <ScrollView showsVerticalScrollIndicator={false}>
                        {/* Title */}
                        <Text style={styles.inputLabel}>Title *</Text>
                        <TextInput
                            style={styles.input}
                            placeholder="e.g. Freelance Writing"
                            placeholderTextColor={COLORS.textSecondary}
                            value={formData.title}
                            onChangeText={(val) => updateField('title', val)}
                        />

                        {/* Description */}
                        <Text style={styles.inputLabel}>Short Description *</Text>
                        <TextInput
                            style={styles.input}
                            placeholder="Brief description"
                            placeholderTextColor={COLORS.textSecondary}
                            value={formData.description}
                            onChangeText={(val) => updateField('description', val)}
                            multiline
                        />

                        {/* Difficulty */}
                        <Text style={styles.inputLabel}>Difficulty</Text>
                        <View style={styles.difficultyContainer}>
                            {['Easy', 'Medium', 'Hard'].map((level) => (
                                <TouchableOpacity
                                    key={level}
                                    style={[
                                        styles.difficultyBtn,
                                        formData.difficulty === level && styles.difficultyBtnActive
                                    ]}
                                    onPress={() => updateField('difficulty', level)}
                                >
                                    <Text style={[
                                        styles.difficultyText,
                                        formData.difficulty === level && styles.difficultyTextActive
                                    ]}>
                                        {level}
                                    </Text>
                                </TouchableOpacity>
                            ))}
                        </View>

                        {/* Pay Range */}
                        <Text style={styles.inputLabel}>Pay Range *</Text>
                        <TextInput
                            style={styles.input}
                            placeholder="e.g. ₱ 50–200 per article"
                            placeholderTextColor={COLORS.textSecondary}
                            value={formData.payRange}
                            onChangeText={(val) => updateField('payRange', val)}
                        />

                        {/* Time Commitment */}
                        <Text style={styles.inputLabel}>Time Commitment *</Text>
                        <TextInput
                            style={styles.input}
                            placeholder="e.g. 5–10 hrs/week"
                            placeholderTextColor={COLORS.textSecondary}
                            value={formData.timeCommitment}
                            onChangeText={(val) => updateField('timeCommitment', val)}
                        />

                        {/* Tags */}
                        <Text style={styles.inputLabel}>Tags (comma-separated)</Text>
                        <TextInput
                            style={styles.input}
                            placeholder="e.g. Writing, Remote, Flexible"
                            placeholderTextColor={COLORS.textSecondary}
                            value={formData.tags}
                            onChangeText={(val) => updateField('tags', val)}
                        />

                        {/* Full Description */}
                        <Text style={styles.inputLabel}>Full Description</Text>
                        <TextInput
                            style={[styles.input, styles.textArea]}
                            placeholder="Detailed description of the job"
                            placeholderTextColor={COLORS.textSecondary}
                            value={formData.fullDescription}
                            onChangeText={(val) => updateField('fullDescription', val)}
                            multiline
                            numberOfLines={4}
                        />

                        {/* Requirements */}
                        <Text style={styles.inputLabel}>Requirements (one per line)</Text>
                        <TextInput
                            style={[styles.input, styles.textArea]}
                            placeholder="Good writing skills&#10;Basic grammar knowledge&#10;Internet connection"
                            placeholderTextColor={COLORS.textSecondary}
                            value={formData.requirements}
                            onChangeText={(val) => updateField('requirements', val)}
                            multiline
                            numberOfLines={4}
                        />

                        {/* How to Start */}
                        <Text style={styles.inputLabel}>How to Start</Text>
                        <TextInput
                            style={[styles.input, styles.textArea]}
                            placeholder="Instructions on how to get started"
                            placeholderTextColor={COLORS.textSecondary}
                            value={formData.howToStart}
                            onChangeText={(val) => updateField('howToStart', val)}
                            multiline
                            numberOfLines={3}
                        />

                        {/* Published Toggle */}
                        <View style={styles.switchContainer}>
                            <Text style={styles.inputLabel}>Published</Text>
                            <Switch
                                value={formData.isPublished}
                                onValueChange={(val) => updateField('isPublished', val)}
                                trackColor={{ false: '#767577', true: COLORS.primary }}
                                thumbColor={formData.isPublished ? COLORS.yellow : '#f4f3f4'}
                            />
                        </View>
                    </ScrollView>

                    <View style={styles.modalButtons}>
                        <TouchableOpacity
                            style={[styles.modalBtn, styles.cancelBtn]}
                            onPress={() => onClose(false)}
                        >
                            <Text style={styles.modalBtnText}>Cancel</Text>
                        </TouchableOpacity>

                        <TouchableOpacity
                            style={[styles.modalBtn, styles.saveBtn]}
                            onPress={handleSubmit}
                            disabled={loading}
                        >
                            <Text style={styles.modalBtnText}>
                                {loading ? 'Saving...' : (job ? 'Update' : 'Create')}
                            </Text>
                        </TouchableOpacity>
                    </View>
                </View>
            </KeyboardAvoidingView>
        </Modal>
    );
};

const styles = StyleSheet.create({
    modalOverlay: {
        flex: 1,
        backgroundColor: 'rgba(0, 0, 0, 0.7)',
        justifyContent: 'center',
        alignItems: 'center',
    },
    modalContent: {
        width: '90%',
        maxHeight: '90%',
        borderRadius: moderateScale(20),
        padding: scale(24),
        overflow: 'hidden',
    },
    gradientFill: {
        position: 'absolute',
        left: 0,
        right: 0,
        top: 0,
        bottom: 0,
    },
    modalHeader: {
        flexDirection: 'row',
        justifyContent: 'space-between',
        alignItems: 'center',
        marginBottom: verticalScale(16),
    },
    modalTitle: {
        fontSize: moderateScale(24),
        fontFamily: 'Poppins-Bold',
        color: COLORS.yellow,
    },
    inputLabel: {
        color: COLORS.text,
        fontSize: moderateScale(14),
        fontFamily: 'Poppins-Medium',
        marginTop: verticalScale(12),
        marginBottom: verticalScale(6),
    },
    input: {
        backgroundColor: COLORS.inputBg,
        color: COLORS.text,
        padding: scale(12),
        borderRadius: moderateScale(12),
        fontSize: moderateScale(14),
        fontFamily: 'Poppins-Regular',
        borderWidth: 1,
        borderColor: '#433DA3',
    },
    textArea: {
        minHeight: verticalScale(80),
        textAlignVertical: 'top',
    },
    difficultyContainer: {
        flexDirection: 'row',
        justifyContent: 'space-between',
        marginBottom: verticalScale(8),
    },
    difficultyBtn: {
        flex: 1,
        paddingVertical: verticalScale(10),
        marginHorizontal: scale(4),
        borderRadius: moderateScale(10),
        backgroundColor: COLORS.inputBg,
        alignItems: 'center',
        borderWidth: 1,
        borderColor: '#433DA3',
    },
    difficultyBtnActive: {
        backgroundColor: COLORS.primary,
        borderColor: COLORS.primary,
    },
    difficultyText: {
        color: COLORS.textSecondary,
        fontFamily: 'Poppins-SemiBold',
        fontSize: moderateScale(12),
    },
    difficultyTextActive: {
        color: COLORS.text,
    },
    switchContainer: {
        flexDirection: 'row',
        justifyContent: 'space-between',
        alignItems: 'center',
        marginTop: verticalScale(12),
        marginBottom: verticalScale(8),
    },
    modalButtons: {
        flexDirection: 'row',
        justifyContent: 'space-between',
        marginTop: verticalScale(24),
    },
    modalBtn: {
        flex: 1,
        paddingVertical: verticalScale(12),
        borderRadius: moderateScale(12),
        alignItems: 'center',
        marginHorizontal: scale(6),
    },
    cancelBtn: {
        backgroundColor: '#433DA3',
    },
    saveBtn: {
        backgroundColor: COLORS.primary,
    },
    modalBtnText: {
        color: '#FFFFFF',
        fontFamily: 'Poppins-Bold',
        fontSize: moderateScale(14),
    },
});

export default JobFormModal;
