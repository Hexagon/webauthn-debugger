function getConfig() {
    const config = JSON.parse($('#config').val());
    console.log(config);
    return config;
}
export { getConfig };