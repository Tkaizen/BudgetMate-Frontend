import React, { useState } from 'react';
import { View, Text, TouchableOpacity, ScrollView, Alert, StyleSheet } from 'react-native';
import { Ionicons } from '@expo/vector-icons';
import { moderateScale, verticalScale, scale } from '../utils/responsive';
import { deleteJob } from '../api/api';
import JobFormModal from './JobFormModal';

const COLORS = {
    background: '#141326',
    cardBg: '#433DA3',
    primary: '#E3823C',
    accent: '#E33C3C',
    text: '#FFFFFF',
    textSecondary: '#D7C7EC',
    yellow: '#FFC107',
    success: '#4CAF50',
    unpublished: '#FF9800',
};

const AdminJobPanel = ({ jobs, onRefresh }) => {
    const [formModalVisible, setFormModalVisible] = useState(false);
    const [editingJob, setEditingJob] = useState(null);

    const handleAddNew = () => {
        setEditingJob(null);
        setFormModalVisible(true);
    };

    const handleEdit = (job) => {
        setEditingJob(job);
        setFormModalVisible(true);
    };

    const handleDelete = (job) => {
        Alert.alert(
            'Delete Job',
            `Are you sure you want to delete "${job.title}"?`,
            [
                { text: 'Cancel', style: 'cancel' },
                {
                    text: 'Delete',
                    style: 'destructive',
                    onPress: async () => {
                        try {
                            await deleteJob(job._id);
                            Alert.alert('Success', 'Job deleted successfully');
                            onRefresh();
                        } catch (error) {
                            console.error('Error deleting job:', error);
                            Alert.alert('Error', 'Failed to delete job');
                        }
                    },
                },
            ]
        );
    };

    const handleFormClose = (shouldRefresh) => {
        setFormModalVisible(false);
        setEditingJob(null);
        if (shouldRefresh) {
            onRefresh();
        }
    };

    return (
        <View style={styles.container}>
            <View style={styles.header}>
                <View style={styles.headerLeft}>
                    <Ionicons name="shield-checkmark" size={moderateScale(24)} color={COLORS.yellow} />
                    <Text style={styles.headerTitle}>Admin Panel</Text>
                </View>
                <TouchableOpacity style={styles.addButton} onPress={handleAddNew}>
                    <Ionicons name="add-circle" size={moderateScale(20)} color={COLORS.text} />
                    <Text style={styles.addButtonText}>Add Job</Text>
                </TouchableOpacity>
            </View>

            <ScrollView
                horizontal
                showsHorizontalScrollIndicator={false}
                contentContainerStyle={styles.jobsList}
            >
                {jobs.length === 0 ? (
                    <View style={styles.emptyState}>
                        <Text style={styles.emptyText}>No jobs yet. Add your first job!</Text>
                    </View>
                ) : (
                    jobs.map((job) => (
                        <View key={job._id} style={styles.jobCard}>
                            <View style={styles.jobHeader}>
                                <Text style={styles.jobTitle} numberOfLines={1}>
                                    {job.title}
                                </Text>
                                <View style={[
                                    styles.statusBadge,
                                    { backgroundColor: job.isPublished ? COLORS.success : COLORS.unpublished }
                                ]}>
                                    <Text style={styles.statusText}>
                                        {job.isPublished ? 'Published' : 'Draft'}
                                    </Text>
                                </View>
                            </View>

                            <Text style={styles.jobDescription} numberOfLines={2}>
                                {job.description}
                            </Text>

                            <View style={styles.jobActions}>
                                <TouchableOpacity
                                    style={[styles.actionBtn, styles.editBtn]}
                                    onPress={() => handleEdit(job)}
                                >
                                    <Ionicons name="create-outline" size={moderateScale(16)} color={COLORS.text} />
                                    <Text style={styles.actionBtnText}>Edit</Text>
                                </TouchableOpacity>

                                <TouchableOpacity
                                    style={[styles.actionBtn, styles.deleteBtn]}
                                    onPress={() => handleDelete(job)}
                                >
                                    <Ionicons name="trash-outline" size={moderateScale(16)} color={COLORS.text} />
                                    <Text style={styles.actionBtnText}>Delete</Text>
                                </TouchableOpacity>
                            </View>
                        </View>
                    ))
                )}
            </ScrollView>

            <JobFormModal
                visible={formModalVisible}
                job={editingJob}
                onClose={handleFormClose}
            />
        </View>
    );
};

const styles = StyleSheet.create({
    container: {
        backgroundColor: '#1F1C3E',
        borderRadius: moderateScale(16),
        padding: scale(16),
        marginTop: verticalScale(10),
        marginBottom: verticalScale(16),
        borderWidth: 2,
        borderColor: COLORS.yellow,
    },
    header: {
        flexDirection: 'row',
        justifyContent: 'space-between',
        alignItems: 'center',
        marginBottom: verticalScale(12),
    },
    headerLeft: {
        flexDirection: 'row',
        alignItems: 'center',
    },
    headerTitle: {
        fontSize: moderateScale(18),
        fontFamily: 'Poppins-Bold',
        color: COLORS.yellow,
        marginLeft: scale(8),
    },
    addButton: {
        flexDirection: 'row',
        alignItems: 'center',
        backgroundColor: COLORS.primary,
        paddingHorizontal: scale(12),
        paddingVertical: verticalScale(8),
        borderRadius: moderateScale(10),
    },
    addButtonText: {
        color: COLORS.text,
        fontFamily: 'Poppins-SemiBold',
        fontSize: moderateScale(12),
        marginLeft: scale(4),
    },
    jobsList: {
        paddingRight: scale(16),
    },
    emptyState: {
        width: scale(300),
        alignItems: 'center',
        justifyContent: 'center',
        paddingVertical: verticalScale(20),
    },
    emptyText: {
        color: COLORS.textSecondary,
        fontFamily: 'Poppins-Regular',
        fontSize: moderateScale(14),
    },
    jobCard: {
        backgroundColor: COLORS.cardBg,
        borderRadius: moderateScale(12),
        padding: scale(12),
        marginRight: scale(12),
        width: scale(250),
    },
    jobHeader: {
        flexDirection: 'row',
        justifyContent: 'space-between',
        alignItems: 'flex-start',
        marginBottom: verticalScale(8),
    },
    jobTitle: {
        fontSize: moderateScale(16),
        fontFamily: 'Poppins-Bold',
        color: COLORS.text,
        flex: 1,
        marginRight: scale(8),
    },
    statusBadge: {
        paddingHorizontal: scale(8),
        paddingVertical: verticalScale(4),
        borderRadius: moderateScale(6),
    },
    statusText: {
        fontSize: moderateScale(10),
        fontFamily: 'Poppins-SemiBold',
        color: COLORS.text,
    },
    jobDescription: {
        fontSize: moderateScale(12),
        fontFamily: 'Poppins-Regular',
        color: COLORS.textSecondary,
        marginBottom: verticalScale(12),
        lineHeight: moderateScale(18),
    },
    jobActions: {
        flexDirection: 'row',
        justifyContent: 'space-between',
    },
    actionBtn: {
        flex: 1,
        flexDirection: 'row',
        alignItems: 'center',
        justifyContent: 'center',
        paddingVertical: verticalScale(8),
        borderRadius: moderateScale(8),
        marginHorizontal: scale(4),
    },
    editBtn: {
        backgroundColor: '#2B2769',
    },
    deleteBtn: {
        backgroundColor: COLORS.accent,
    },
    actionBtnText: {
        color: COLORS.text,
        fontFamily: 'Poppins-SemiBold',
        fontSize: moderateScale(12),
        marginLeft: scale(4),
    },
});

export default AdminJobPanel;
