// Chave de API do VirusTotal
const apiKey = "ab894ff132dcdd904200f69439fd3834311e512943dfdd1c19968ada02f59836";

// Função para verificar o arquivo com a API do VirusTotal
async function verificarArquivo(file) {
    const formData = new FormData();
    formData.append('file', file);

    try {
        // Enviar o arquivo para o VirusTotal
        const response = await fetch('https://www.virustotal.com/api/v3/files', {
            method: 'POST',
            headers: {
                'x-apikey': apiKey,
            },
            body: formData,
        });

        const data = await response.json();

        if (data.data) {
            // Arquivo enviado com sucesso
            const fileId = data.data.id;
            // Obter os resultados da verificação
            await obterResultado(fileId);
        } else {
            document.getElementById('result').innerHTML = "Erro ao verificar o arquivo.";
        }
    } catch (error) {
        document.getElementById('result').innerHTML = "Erro na requisição à API: " + error;
    }
}

// Função para verificar a URL com a API do VirusTotal
async function verificarURL(url) {
    try {
        // Enviar a URL para o VirusTotal
        const response = await fetch(`https://www.virustotal.com/api/v3/urls/${encodeURIComponent(url)}`, {
            headers: {
                'x-apikey': apiKey,
            },
        });

        const data = await response.json();

        if (data.data) {
            // URL enviada com sucesso
            await obterResultadoURL(data.data.id);
        } else {
            document.getElementById('result').innerHTML = "Erro ao verificar a URL.";
        }
    } catch (error) {
        document.getElementById('result').innerHTML = "Erro na requisição à API: " + error;
    }
}

// Função para obter os resultados da verificação de arquivo
async function obterResultado(fileId) {
    try {
        // Obter os resultados do arquivo
        const response = await fetch(`https://www.virustotal.com/api/v3/files/${fileId}`, {
            headers: {
                'x-apikey': apiKey,
            },
        });

        const data = await response.json();

        // Exibir o resultado da verificação
        const resultContainer = document.getElementById('result');
        if (data.data.attributes.last_analysis_stats) {
            const stats = data.data.attributes.last_analysis_stats;
            resultContainer.innerHTML = `
                <h3>Resultado da Verificação (Arquivo):</h3>
                <p>Riscos encontrados: ${stats.malicious} Malicioso</p>
                <p>Não Malicioso: ${stats.harmless}</p>
                <p>Desconhecido: ${stats.undetected}</p>
            `;
        } else {
            resultContainer.innerHTML = "Erro ao obter os resultados.";
        }
    } catch (error) {
        document.getElementById('result').innerHTML = "Erro na requisição para obter resultados: " + error;
    }
}

// Função para obter os resultados da verificação de URL
async function obterResultadoURL(urlId) {
    try {
        // Obter os resultados da URL
        const response = await fetch(`https://www.virustotal.com/api/v3/urls/${urlId}`, {
            headers: {
                'x-apikey': apiKey,
            },
        });

        const data = await response.json();

        // Exibir o resultado da verificação
        const resultContainer = document.getElementById('result');
        if (data.data.attributes.last_analysis_stats) {
            const stats = data.data.attributes.last_analysis_stats;
            resultContainer.innerHTML = `
                <h3>Resultado da Verificação (URL):</h3>
                <p>Riscos encontrados: ${stats.malicious} Malicioso</p>
                <p>Não Malicioso: ${stats.harmless}</p>
                <p>Desconhecido: ${stats.undetected}</p>
            `;
        } else {
            resultContainer.innerHTML = "Erro ao obter os resultados.";
        }
    } catch (error) {
        document.getElementById('result').innerHTML = "Erro na requisição para obter resultados: " + error;
    }
}

// Adicionar o evento de envio do formulário de arquivo
document.getElementById('file-form').addEventListener('submit', function(event) {
    event.preventDefault();
    const fileInput = document.getElementById('file-input');
    if (fileInput.files.length > 0) {
        const file = fileInput.files[0];
        verificarArquivo(file);
    } else {
        alert("Por favor, selecione um arquivo.");
    }
});

// Adicionar o evento de envio do formulário de URL
document.getElementById('url-form').addEventListener('submit', function(event) {
    event.preventDefault();
    const urlInput = document.getElementById('url-input');
    const url = urlInput.value.trim();
    if (url) {
        verificarURL(url);
    } else {
        alert("Por favor, insira uma URL.");
    }
});
