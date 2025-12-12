import React, { useState, useCallback } from 'react';
import { View, Text, TextInput, TouchableOpacity, ScrollView, Alert, Modal, KeyboardAvoidingView, Platform } from 'react-native';
import { SafeAreaView } from 'react-native-safe-area-context';
import { StatusBar } from 'expo-status-bar';
import { moderateScale, verticalScale } from '../../../src/utils/responsive';
import { Ionicons } from '@expo/vector-icons';
import AsyncStorage from '@react-native-async-storage/async-storage';
import { useFocusEffect } from 'expo-router';
import { LinearGradient } from 'expo-linear-gradient';
import JobCard from '../../../src/components/JobCard';
import EarningsChart from '../../../src/components/budget/EarningsChart';
import AdminJobPanel from '../../../src/components/AdminJobPanel';
import { fetchJobs } from '../../../src/api/api';
import { styles, COLORS } from './styles';


const Earn = () => {
    const [monthlyTotal, setMonthlyTotal] = useState(0);
    const [chartData, setChartData] = useState(Array(12).fill(0));
    const [loading, setLoading] = useState(true);
    const [searchQuery, setSearchQuery] = useState('');
    const [selectedJob, setSelectedJob] = useState(null);
    const [jobModalVisible, setJobModalVisible] = useState(false);
    const [seeAllModalVisible, setSeeAllModalVisible] = useState(false);
    const [user, setUser] = useState(null);
    const [jobs, setJobs] = useState([]);
    const [jobsLoading, setJobsLoading] = useState(true);

    // Add Earning State
    const [addEarningModalVisible, setAddEarningModalVisible] = useState(false);
    const [newAmount, setNewAmount] = useState('');
    const [newSource, setNewSource] = useState('');

    // Load earnings from AsyncStorage and compute current month total + chart data
    // Action: Load Earnings from Storage
    // We store earnings locally in a JSON array.
    // This function calculates the total for the current month to display on the dashboard.
    const loadEarnings = async () => {
        setLoading(true);
        try {
            // 1. Get current user ID to ensure we load the correct data
            const userDataStr = await AsyncStorage.getItem('userData');
            const user = userDataStr ? JSON.parse(userDataStr) : null;
            const storageKey = user?.id ? `earnings_${user.id}` : 'earnings';

            // 2. Read the raw JSON string
            const raw = await AsyncStorage.getItem(storageKey);
            let entries = [];
            if (raw) {
                entries = JSON.parse(raw);
            }

            // 3. Current Date Info
            const now = new Date();
            const currentYear = now.getFullYear();
            const currentMonth = now.getMonth(); // 0-11 (Jan is 0)

            let total = 0;
            const monthlyData = Array(12).fill(0);

            // 4. Loop through entries to sum up amounts
            entries.forEach(e => {
                try {
                    const d = new Date(e.date);
                    // Only count for current year
                    if (d.getFullYear() === currentYear) {
                        const amount = Number(e.amount) || 0;
                        monthlyData[d.getMonth()] += amount;

                        // Check if it matches current month
                        if (d.getMonth() === currentMonth) {
                            total += amount;
                        }
                    }
                } catch (err) {
                    // ignore invalid dates
                }
            });

            setMonthlyTotal(total);
            setChartData(monthlyData);
        } catch (err) {
            console.error('Failed to load earnings', err);
            setMonthlyTotal(0);
        } finally {
            setLoading(false);
        }
    };

    // Load jobs from API
    const loadJobs = async () => {
        setJobsLoading(true);
        try {
            const response = await fetchJobs();
            setJobs(response.jobs || []);
        } catch (error) {
            console.error('Error loading jobs:', error);
            setJobs([]);
        } finally {
            setJobsLoading(false);
        }
    };

    // Load user data to check if admin
    const loadUser = async () => {
        try {
            const userDataStr = await AsyncStorage.getItem('userData');
            if (userDataStr) {
                const userData = JSON.parse(userDataStr);
                setUser(userData);
            }
        } catch (error) {
            console.error('Error loading user data:', error);
        }
    };

    useFocusEffect(
        useCallback(() => {
            loadEarnings();
            loadJobs();
            loadUser();
        }, [])
    );

    const formatCurrency = (n) => {
        return `₱ ${Number(n || 0).toLocaleString(undefined, { minimumFractionDigits: 2, maximumFractionDigits: 2 })}`;
    };

    const handleAddEarning = async () => {
        if (!newAmount) {
            Alert.alert('Error', 'Please enter an amount');
            return;
        }

        try {
            // Get current user ID
            const userDataStr = await AsyncStorage.getItem('userData');
            const user = userDataStr ? JSON.parse(userDataStr) : null;
            const storageKey = user?.id ? `earnings_${user.id}` : 'earnings';

            const raw = await AsyncStorage.getItem(storageKey);
            const entries = raw ? JSON.parse(raw) : [];

            const entry = {
                id: Date.now().toString(),
                amount: parseFloat(newAmount),
                source: newSource || 'Other',
                date: new Date().toISOString()
            };

            entries.push(entry);
            await AsyncStorage.setItem(storageKey, JSON.stringify(entries));

            setAddEarningModalVisible(false);
            setNewAmount('');
            setNewSource('');
            Alert.alert('Success', 'Earning logged successfully!');
            loadEarnings();
        } catch (err) {
            console.error('Failed to add earning', err);
            Alert.alert('Error', 'Could not save earning');
        }
    };

    // Search Functionality
    // Filters the jobs array based on title, description, or tags matching the search query.
    const filteredJobs = jobs.filter(job =>
        job.title.toLowerCase().includes(searchQuery.toLowerCase()) ||
        job.description.toLowerCase().includes(searchQuery.toLowerCase()) ||
        (job.tags && job.tags.some(tag => tag.toLowerCase().includes(searchQuery.toLowerCase())))
    );

    const handleLearnMore = (job) => {
        setSelectedJob(job);
        setJobModalVisible(true);
    };

    return (
        <SafeAreaView style={styles.container}>
            <StatusBar style="light" backgroundColor={COLORS.background} />

            {/* Add Earning Modal */}
            <Modal
                animationType="slide"
                transparent={true}
                visible={addEarningModalVisible}
                onRequestClose={() => setAddEarningModalVisible(false)}
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

                        <Text style={styles.modalTitle}>Log New Earning</Text>

                        <Text style={styles.inputLabel}>Amount (₱)</Text>
                        <TextInput
                            style={styles.input}
                            placeholder="0.00"
                            placeholderTextColor={COLORS.textSecondary}
                            keyboardType="numeric"
                            value={newAmount}
                            onChangeText={setNewAmount}
                        />

                        <Text style={styles.inputLabel}>Source (Optional)</Text>
                        <TextInput
                            style={styles.input}
                            placeholder="e.g. Freelance, Salary"
                            placeholderTextColor={COLORS.textSecondary}
                            value={newSource}
                            onChangeText={setNewSource}
                        />

                        <View style={styles.modalButtons}>
                            <TouchableOpacity
                                style={[styles.modalBtn, styles.cancelBtn]}
                                onPress={() => setAddEarningModalVisible(false)}
                            >
                                <Text style={styles.modalBtnText}>Cancel</Text>
                            </TouchableOpacity>

                            <TouchableOpacity
                                style={[styles.modalBtn, styles.saveBtn]}
                                onPress={handleAddEarning}
                            >
                                <Text style={styles.modalBtnText}>Save</Text>
                            </TouchableOpacity>
                        </View>
                    </View>
                </KeyboardAvoidingView>
            </Modal>

            {/* See All Jobs Modal */}
            <Modal
                animationType="slide"
                transparent={true}
                visible={seeAllModalVisible}
                onRequestClose={() => setSeeAllModalVisible(false)}
            >
                <View style={styles.modalOverlay}>
                    <View style={styles.modalContent}>
                        <LinearGradient
                            colors={['#433DA3', '#2B2769', '#19173D']}
                            locations={[0.1, 0.45, 0.75]}
                            style={styles.gradientFill}
                        />

                        <View style={styles.modalHeader}>
                            <Text style={styles.modalTitle}>All Jobs</Text>
                            <TouchableOpacity onPress={() => setSeeAllModalVisible(false)}>
                                <Ionicons name="close" size={24} color={COLORS.text} />
                            </TouchableOpacity>
                        </View>

                        <ScrollView showsVerticalScrollIndicator={false}>
                            {filteredJobs.map((job) => (
                                <JobCard
                                    key={job._id || job.id}
                                    job={job}
                                    onPress={(j) => {
                                        setSeeAllModalVisible(false);
                                        handleLearnMore(j);
                                    }}
                                    style={{ width: '100%', marginBottom: verticalScale(16) }}
                                />
                            ))}
                        </ScrollView>
                    </View>
                </View>
            </Modal>

            {/* Job Details Modal */}
            <Modal
                animationType="slide"
                transparent={true}
                visible={jobModalVisible}
                onRequestClose={() => setJobModalVisible(false)}
            >
                <View style={styles.modalOverlay}>
                    <View style={styles.modalContent}>
                        <LinearGradient
                            colors={['#433DA3', '#2B2769', '#19173D']}
                            locations={[0.1, 0.45, 0.75]}
                            style={styles.gradientFill}
                        />

                        <ScrollView showsVerticalScrollIndicator={false}>
                            <Text style={styles.modalTitle}>{selectedJob?.title}</Text>
                            <View style={styles.modalBadge}>
                                <Text style={styles.modalBadgeText}>{selectedJob?.difficulty}</Text>
                            </View>

                            <Text style={styles.modalSectionTitle}>About</Text>
                            <Text style={styles.modalText}>{selectedJob?.fullDescription}</Text>

                            <Text style={styles.modalSectionTitle}>Pay & Time</Text>
                            <Text style={styles.modalText}>• {selectedJob?.payRange}</Text>
                            <Text style={styles.modalText}>• {selectedJob?.timeCommitment}</Text>

                            <Text style={styles.modalSectionTitle}>Requirements</Text>
                            {selectedJob?.requirements.map((req, index) => (
                                <Text key={index} style={styles.modalText}>• {req}</Text>
                            ))}

                            <Text style={styles.modalSectionTitle}>How to Start</Text>
                            <Text style={styles.modalText}>{selectedJob?.howToStart}</Text>
                        </ScrollView>

                        <TouchableOpacity
                            style={styles.closeButton}
                            onPress={() => setJobModalVisible(false)}
                        >
                            <Text style={styles.closeButtonText}>Close</Text>
                        </TouchableOpacity>
                    </View>
                </View>
            </Modal>

            <ScrollView contentContainerStyle={styles.scrollContent} showsVerticalScrollIndicator={false}>

                {/* Search bar */}
                <View style={styles.searchContainer}>
                    <Ionicons name="search" size={moderateScale(18)} color="#A0A0A0" />
                    <TextInput
                        placeholder="Find Job"
                        placeholderTextColor="#A0A0A0"
                        style={styles.searchInput}
                        value={searchQuery}
                        onChangeText={setSearchQuery}
                    />
                    {searchQuery.length > 0 && (
                        <TouchableOpacity onPress={() => setSearchQuery('')}>
                            <Ionicons name="close-circle" size={moderateScale(18)} color="#A0A0A0" />
                        </TouchableOpacity>
                    )}
                </View>

                {/* Admin Panel - Only visible to admins */}
                {user && user.role === 'admin' && (
                    <AdminJobPanel jobs={jobs} onRefresh={loadJobs} />
                )}

                {/* Jobs Section */}
                <View style={styles.sectionHeader}>
                    <Text style={styles.sectionTitle}>Available Jobs</Text>
                    <TouchableOpacity onPress={() => setSeeAllModalVisible(true)}>
                        <Text style={styles.seeAllText}>See all</Text>
                    </TouchableOpacity>
                </View>

                <ScrollView
                    horizontal
                    showsHorizontalScrollIndicator={false}
                    contentContainerStyle={styles.jobsScroll}
                >
                    {jobsLoading ? (
                        <View style={styles.emptySearch}>
                            <Text style={styles.emptySearchText}>Loading jobs...</Text>
                        </View>
                    ) : filteredJobs.length > 0 ? (
                        filteredJobs.map((job) => (
                            <JobCard key={job._id || job.id} job={job} onPress={handleLearnMore} />
                        ))
                    ) : (
                        <View style={styles.emptySearch}>
                            <Text style={styles.emptySearchText}>No jobs found</Text>
                        </View>
                    )}
                </ScrollView>

                {/* Earnings Section */}
                <View style={styles.earningsContainer}>
                    <Text style={styles.earningsAmount}>{loading ? 'Loading...' : formatCurrency(monthlyTotal)}</Text>
                    <Text style={styles.earningsText}>
                        Total earned this month. <Text style={styles.detailsLink}>See details</Text>
                    </Text>

                    <TouchableOpacity
                        style={[styles.learnMoreBtn, { marginTop: verticalScale(12) }]}
                        onPress={() => setAddEarningModalVisible(true)}
                    >
                        <Text style={styles.learnMoreText}>Log New Earning</Text>
                    </TouchableOpacity>
                </View>

                {/* Bar Chart */}
                <View style={styles.chartWrapper}>
                    <EarningsChart earningsData={chartData} />
                </View>

            </ScrollView>
        </SafeAreaView>
    );
};

export default Earn;
