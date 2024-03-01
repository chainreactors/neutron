package file

import (
	"bufio"
	"errors"
	"fmt"
	"github.com/chainreactors/neutron/common"
	"github.com/chainreactors/neutron/operators"
	"github.com/chainreactors/neutron/protocols"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/mholt/archiver"
)

var _ protocols.Request = &Request{}

// Type returns the type of the protocol request
func (request *Request) Type() protocols.ProtocolType {
	return protocols.FileProtocol
}

type FileMatch struct {
	Data      string
	Line      int
	ByteIndex int
	Match     bool
	Extract   bool
	Expr      string
	Raw       string
}

var emptyResultErr = errors.New("Empty result")

// ExecuteWithResults executes the protocol requests and returns results instead of writing them.
func (request *Request) ExecuteWithResults(input *protocols.ScanContext, previous map[string]interface{}, callback protocols.OutputEventCallback) error {
	//wg := sizedwaitgroup.NewGenerator(request.options.Options.BulkSize)
	err := request.getInputPaths(input.Input, func(filePath string) {
		//wg.Add()
		func(filePath string) {
			//defer wg.Done()
			archiveReader, _ := archiver.ByExtension(filePath)
			switch {
			case archiveReader != nil:
				switch archiveInstance := archiveReader.(type) {
				case archiver.Walker:
					err := archiveInstance.Walk(filePath, func(file archiver.File) error {
						if !request.validatePath("/", file.Name(), true) {
							return nil
						}
						// every new file in the compressed multi-file archive counts 1
						//request.options.Progress.AddToTotal(1)
						archiveFileName := filepath.Join(filePath, file.Name())
						event, fileMatches, err := request.processReader(file.ReadCloser, archiveFileName, input.Input, file.Size(), previous)
						if err != nil {
							if errors.Is(err, emptyResultErr) {
								// no matches but one file elaborated
								//request.options.Progress.IncrementRequests()
								return nil
							}
							common.NeutronLog.Errorf("%s\n", err)
							// error while elaborating the file
							//request.options.Progress.IncrementFailedRequestsBy(1)
							return err
						}
						defer file.Close()
						dumpResponse(event, request.options, fileMatches, filePath)
						callback(event)
						// file elaborated and matched
						//request.options.Progress.IncrementRequests()
						return nil
					})
					if err != nil {
						common.NeutronLog.Errorf("%s\n", err)
						return
					}
				case archiver.Decompressor:
					// compressed archive - contains only one file => increments the counter by 1
					//request.options.Progress.AddToTotal(1)
					file, err := os.Open(filePath)
					if err != nil {
						common.NeutronLog.Errorf("%s\n", err)
						// error while elaborating the file
						//request.options.Progress.IncrementFailedRequestsBy(1)
						return
					}
					defer file.Close()
					fileStat, _ := file.Stat()
					tmpFileOut, err := os.CreateTemp("", "")
					if err != nil {
						common.NeutronLog.Errorf("%s\n", err)
						// error while elaborating the file
						//request.options.Progress.IncrementFailedRequestsBy(1)
						return
					}
					defer tmpFileOut.Close()
					defer os.RemoveAll(tmpFileOut.Name())
					if err := archiveInstance.Decompress(file, tmpFileOut); err != nil {
						common.NeutronLog.Errorf("%s\n", err)
						// error while elaborating the file
						//request.options.Progress.IncrementFailedRequestsBy(1)
						return
					}
					_ = tmpFileOut.Sync()
					// rewind the file
					_, _ = tmpFileOut.Seek(0, 0)
					event, fileMatches, err := request.processReader(tmpFileOut, filePath, input.Input, fileStat.Size(), previous)
					if err != nil {
						if errors.Is(err, emptyResultErr) {
							// no matches but one file elaborated
							//request.options.Progress.IncrementRequests()
							return
						}
						//gologger.Error().Msgf("%s\n", err)
						// error while elaborating the file
						//request.options.Progress.IncrementFailedRequestsBy(1)
						return
					}
					dumpResponse(event, request.options, fileMatches, filePath)
					callback(event)
					// file elaborated and matched
					//request.options.Progress.IncrementRequests()
				}
			default:
				// normal file - increments the counter by 1
				//request.options.Progress.AddToTotal(1)
				event, fileMatches, err := request.processFile(filePath, input.Input, previous)
				if err != nil {
					if errors.Is(err, emptyResultErr) {
						// no matches but one file elaborated
						//request.options.Progress.IncrementRequests()
						return
					}
					common.NeutronLog.Errorf("%s\n", err)
					// error while elaborating the file
					//request.options.Progress.IncrementFailedRequestsBy(1)
					return
				}
				dumpResponse(event, request.options, fileMatches, filePath)
				callback(event)
				// file elaborated and matched
				//request.options.Progress.IncrementRequests()
			}
		}(filePath)
	})

	//wg.Wait()
	if err != nil {
		//request.options.Output.Request(request.options.TemplatePath, input, request.Type().String(), err)
		//request.options.Progress.IncrementFailedRequestsBy(1)
		return fmt.Errorf("could not send file request, %s", err)
	}
	return nil
}

func (request *Request) processFile(filePath, input string, previousInternalEvent protocols.InternalEvent) (*protocols.InternalWrappedEvent, []FileMatch, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return nil, nil, fmt.Errorf("Could not open file path %s: %s\n", filePath, err)
	}
	defer file.Close()

	stat, err := file.Stat()
	if err != nil {
		return nil, nil, fmt.Errorf("Could not stat file path %s: %s\n", filePath, err)
	}
	if stat.Size() >= request.maxSize {
		maxSizeString := common.HumanSize(float64(request.maxSize))
		common.NeutronLog.Debugf("Limiting %s processed data to %s bytes: exceeded max size\n", filePath, maxSizeString)
	}

	return request.processReader(file, filePath, input, stat.Size(), previousInternalEvent)
}

func (request *Request) processReader(reader io.Reader, filePath, input string, totalBytes int64, previousInternalEvent protocols.InternalEvent) (*protocols.InternalWrappedEvent, []FileMatch, error) {
	fileReader := io.LimitReader(reader, request.maxSize)
	fileMatches, opResult := request.findMatchesWithReader(fileReader, input, filePath, totalBytes, previousInternalEvent)
	if opResult == nil && len(fileMatches) == 0 {
		return nil, nil, emptyResultErr
	}

	// build event structure to interface with internal logic
	return request.buildEvent(input, filePath, fileMatches, opResult, previousInternalEvent), fileMatches, nil
}

// MakeResultEvent creates a result event from internal wrapped event
func (r *Request) MakeResultEvent(wrapped *protocols.InternalWrappedEvent) []*protocols.ResultEvent {
	if len(wrapped.OperatorsResult.DynamicValues) > 0 && !wrapped.OperatorsResult.Matched {
		return nil
	}

	results := make([]*protocols.ResultEvent, 0, len(wrapped.OperatorsResult.Matches)+1)

	// If we have multiple matchers with names, write each of them separately.
	if len(wrapped.OperatorsResult.Matches) > 0 {
		for k := range wrapped.OperatorsResult.Matches {
			data := r.MakeResultEventItem(wrapped)
			data.MatcherName = k
			results = append(results, data)
		}
	} else if len(wrapped.OperatorsResult.Extracts) > 0 {
		for k, v := range wrapped.OperatorsResult.Extracts {
			data := r.MakeResultEventItem(wrapped)
			data.ExtractedResults = v
			data.ExtractorName = k
			results = append(results, data)
		}
	} else {
		data := r.MakeResultEventItem(wrapped)
		results = append(results, data)
	}
	return results
}

func (request *Request) findMatchesWithReader(reader io.Reader, input, filePath string, totalBytes int64, previous protocols.InternalEvent) ([]FileMatch, *operators.Result) {
	var bytesCount, linesCount, wordsCount int
	//isResponseDebug := request.options.Options.Debug || request.options.Options.DebugResponse
	//totalBytesString := common.BytesSize(float64(totalBytes))

	scanner := bufio.NewScanner(reader)
	buffer := []byte{}
	if request.CompiledOperators.GetMatchersCondition() == operators.ANDCondition {
		scanner.Buffer(buffer, int(defaultMaxReadSize))
		scanner.Split(func(data []byte, atEOF bool) (advance int, token []byte, err error) {
			defaultMaxReadSizeInt := int(defaultMaxReadSize)
			if len(data) > defaultMaxReadSizeInt {
				return defaultMaxReadSizeInt, data[0:defaultMaxReadSizeInt], nil
			}
			if !atEOF {
				return 0, nil, nil
			}
			return len(data), data, bufio.ErrFinalToken
		})
	} else {
		scanner.Buffer(buffer, int(chunkSize))
	}

	var fileMatches []FileMatch
	var opResult *operators.Result
	for scanner.Scan() {
		lineContent := scanner.Text()
		n := len(lineContent)

		// update counters
		currentBytes := bytesCount + n
		//processedBytes := common.BytesSize(float64(currentBytes))

		//common.NeutronLog.Importantf("[%s] Processing file %s chunk %s/%s", request.options.TemplateID, filePath, processedBytes, totalBytesString)
		dslMap := request.responseToDSLMap(lineContent, input, filePath)
		for k, v := range previous {
			dslMap[k] = v
		}
		discardEvent := protocols.CreateEvent(request, dslMap)
		newOpResult := discardEvent.OperatorsResult
		if newOpResult != nil {
			if opResult == nil {
				opResult = newOpResult
			} else {
				//todo
				//opResult.Merge(newOpResult)
			}
			if newOpResult.Matched || newOpResult.Extracted {
				if newOpResult.Extracts != nil {
					for expr, extracts := range newOpResult.Extracts {
						for _, extract := range extracts {
							fileMatches = append(fileMatches, FileMatch{
								Data:      extract,
								Extract:   true,
								Line:      linesCount + 1,
								ByteIndex: bytesCount,
								Expr:      expr,
								Raw:       lineContent,
							})
						}
					}
				}
				if newOpResult.Matches != nil {
					for expr, matches := range newOpResult.Matches {
						for _, match := range matches {
							fileMatches = append(fileMatches, FileMatch{
								Data:      match,
								Match:     true,
								Line:      linesCount + 1,
								ByteIndex: bytesCount,
								Expr:      expr,
								Raw:       lineContent,
							})
						}
					}
				}
				for _, outputExtract := range newOpResult.OutputExtracts {
					fileMatches = append(fileMatches, FileMatch{
						Data:      outputExtract,
						Match:     true,
						Line:      linesCount + 1,
						ByteIndex: bytesCount,
						Expr:      outputExtract,
						Raw:       lineContent,
					})
				}
			}
		}

		currentLinesCount := 1 + strings.Count(lineContent, "\n")
		linesCount += currentLinesCount
		wordsCount += strings.Count(lineContent, " ")
		bytesCount = currentBytes
	}
	return fileMatches, opResult
}

func (request *Request) buildEvent(input, filePath string, fileMatches []FileMatch, operatorResult *operators.Result, previous protocols.InternalEvent) *protocols.InternalWrappedEvent {
	exprLines := make(map[string][]int)
	exprBytes := make(map[string][]int)
	internalEvent := request.responseToDSLMap("", input, filePath)
	for k, v := range previous {
		internalEvent[k] = v
	}
	for _, fileMatch := range fileMatches {
		exprLines[fileMatch.Expr] = append(exprLines[fileMatch.Expr], fileMatch.Line)
		exprBytes[fileMatch.Expr] = append(exprBytes[fileMatch.Expr], fileMatch.ByteIndex)
	}

	event := protocols.CreateEventWithOperatorResults(request, internalEvent, operatorResult)
	// Annotate with line numbers if asked by the user
	// todo
	//if request.options.Options.ShowMatchLine {
	//	for _, result := range event.Results {
	//		switch {
	//		case result.MatcherName != "":
	//			result.Lines = exprLines[result.MatcherName]
	//		case result.ExtractorName != "":
	//			result.Lines = exprLines[result.ExtractorName]
	//		default:
	//			for _, extractedResult := range result.ExtractedResults {
	//				result.Lines = append(result.Lines, exprLines[extractedResult]...)
	//			}
	//		}
	//		result.Lines = sliceutil.DedupeInt(result.Lines)
	//	}
	//}
	return event
}

func dumpResponse(event *protocols.InternalWrappedEvent, requestOptions *protocols.ExecuterOptions, filematches []FileMatch, filePath string) {
	//cliOptions := requestOptions.Options
	//if cliOptions.Debug || cliOptions.DebugResponse {
	//	for _, fileMatch := range filematches {
	//		lineContent := fileMatch.Raw
	//		hexDump := false
	//		if responsehighlighter.HasBinaryContent(lineContent) {
	//			hexDump = true
	//			lineContent = hex.Dump([]byte(lineContent))
	//		}
	//		highlightedResponse := responsehighlighter.Highlight(event.OperatorsResult, lineContent, cliOptions.NoColor, hexDump)
	//		common.NeutronLog.Debugf("[%s] Dumped match/extract file snippet for %s at line %d\n\n%s", requestOptions.TemplateID, filePath, fileMatch.Line, highlightedResponse)
	//	}
	//}
}
