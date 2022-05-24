function getConfig() {
    const config = JSON.parse($('#config').val());
    return config;
}
export { getConfig };